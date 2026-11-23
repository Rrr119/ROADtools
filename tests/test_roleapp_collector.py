import asyncio
import json
import os
from urllib.parse import parse_qs, urlsplit

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import roadtools.roadlib.metadef.database as database
from roadtools.roadlib.metadef.database import (
    Application,
    Base,
    CollectorObject,
    CollectorState,
    DirectoryRole,
    OAuth2PermissionGrant,
    ServicePrincipal,
)
from roadtools.roadrecon.collector import (
    DEFAULT_RESOURCES,
    AzureADRoleApplicationCollector,
    GraphClient,
)


class FakeResponse:
    def __init__(self, payload, status=200):
        self.payload = payload
        self.status = status
        self.headers = {}

    async def json(self):
        return self.payload

    async def text(self):
        return json.dumps(self.payload)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


class FakeGraph:
    """
    Tiny in-memory Graph replacement.

    Each tenant gets its own instance. The delta token embeds the tenant and
    resource so tests can also assert that cursors are tenant-scoped.
    """

    def __init__(self, tenant):
        self.tenant = tenant
        self.full = {name: [] for name in DEFAULT_RESOURCES}
        self.deltas = {}
        self.version = 1
        self.calls = []

    def delta_link(self, resource):
        return ('https://graph.microsoft.com/v1.0/%s/delta?$deltatoken=%s-%s-v%s'
                % (resource, self.tenant, resource, self.version))

    def set_full(self, resource, values):
        self.full[resource] = list(values)

    def set_delta(self, resource, values, removed_ids=()):
        self.version += 1
        items = list(values)
        for removed_id in removed_ids:
            items.append({'id': removed_id, '@removed': {'reason': 'deleted'}})
        self.deltas[resource] = items

    def session(self):
        return FakeSession(self)


class FakeSession:
    def __init__(self, graph):
        self.graph = graph

    def get(self, url, headers=None):
        self.graph.calls.append(url)
        parts = urlsplit(url)
        path = parts.path.strip('/').split('/')
        if path[-1] == 'delta':
            resource = path[-2]
        else:
            resource = path[-1]
        token = parse_qs(parts.query).get('$deltatoken')
        if token:
            payload = {
                'value': self.graph.deltas.get(resource, []),
                '@odata.deltaLink': self.graph.delta_link(resource),
            }
        elif path[-1] == 'delta':
            payload = {
                'value': self.graph.full.get(resource, []),
                '@odata.deltaLink': self.graph.delta_link(resource),
            }
        else:
            payload = {'value': self.graph.full.get(resource, [])}
        return FakeResponse(payload)


def make_tenant_graph(tenant):
    graph = FakeGraph(tenant)
    graph.set_full('directoryRoles', [{
        'id': '%s-role-1' % tenant,
        'displayName': '%s Global Reader' % tenant,
        'description': 'read-only role for %s' % tenant,
        'roleTemplateId': 'role-template-1',
    }])
    graph.set_full('applications', [
        {
            'id': '%s-app-1' % tenant,
            'appId': '%s-appid-1' % tenant,
            'displayName': '%s Portal' % tenant,
            'signInAudience': 'AzureADMyOrg',
            'appRoles': [{
                'id': 'role-1',
                'displayName': 'Reader',
                'value': 'Reader',
                'isEnabled': True,
            }],
            'web': {
                'redirectUris': ['https://%s.example/callback' % tenant],
                'homePageUrl': 'https://%s.example' % tenant,
            },
        },
        {
            'id': '%s-app-2' % tenant,
            'appId': '%s-appid-2' % tenant,
            'displayName': '%s API' % tenant,
            'signInAudience': 'AzureADMultipleOrgs',
        },
    ])
    graph.set_full('servicePrincipals', [{
        'id': '%s-sp-1' % tenant,
        'appId': '%s-appid-1' % tenant,
        'displayName': '%s Portal SP' % tenant,
        'servicePrincipalType': 'Application',
        'accountEnabled': True,
    }])
    graph.set_full('oauth2PermissionGrants', [{
        'id': '%s-grant-1' % tenant,
        'clientId': '%s-sp-1' % tenant,
        'consentType': 'AllPrincipals',
        'resourceId': '%s-sp-2' % tenant,
        'scope': 'User.Read',
        'startTime': '2024-01-02T03:04:05.123Z',
        'expiryTime': '2025-01-02T03:04:05.1234567Z',
    }])
    return graph


def run_collector(dburl, tenant, graph, resources=DEFAULT_RESOURCES, full=False):
    engine = database.init(False, dburl=dburl)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    try:
        collector = AzureADRoleApplicationCollector(
            tenant,
            session,
            graph_client=GraphClient(graph.session(), headers={}),
        )
        return asyncio.run(collector.collect(
            resources=resources, full=full))
    finally:
        session.close()


def test_three_tenants_share_one_database(tmp_path):
    dbfile = str(tmp_path / 'roadrecon.db')
    dburl = 'sqlite:///' + dbfile

    # Simulate a database created by the legacy AAD Graph collector: only the
    # old tables exist and there is already data in them.
    engine = create_engine(dburl)
    Application.__table__.create(engine)
    session = sessionmaker(bind=engine)()
    session.add(Application(
        objectType='Application',
        objectId='legacy-app',
        appId='legacy-appid',
        displayName='Legacy application',
    ))
    session.commit()
    session.close()

    graphs = {}
    for tenant in ('tenant-a', 'tenant-b', 'tenant-c'):
        graphs[tenant] = make_tenant_graph(tenant)
        results = run_collector(dburl, tenant, graphs[tenant])
        assert all(result.ok for result in results)

    # The additive tables were created without touching the legacy row.
    engine = database.init(False, dburl=dburl)
    session = sessionmaker(bind=engine)()
    assert session.get(Application, 'legacy-app').displayName == 'Legacy application'

    # All three tenants are present in the existing ROADrecon tables.
    assert session.query(Application).count() == 7
    assert session.query(DirectoryRole).count() == 3
    assert session.query(ServicePrincipal).count() == 3
    assert session.query(OAuth2PermissionGrant).count() == 3

    # Each tenant has its own cursors and object ledger entries.
    for tenant in graphs:
        states = session.query(CollectorState).filter_by(tenantId=tenant).all()
        assert len(states) == len(DEFAULT_RESOURCES)
        assert all(state.deltaLink for state in states)
        assert session.query(CollectorObject).filter_by(
            tenantId=tenant, resource='applications').count() == 2

    # Existing columns are populated through the Graph -> AAD Graph mapping.
    app = session.get(Application, 'tenant-b-app-1')
    assert app.appId == 'tenant-b-appid-1'
    assert app.replyUrls == ['https://tenant-b.example/callback']
    assert app.homepage == 'https://tenant-b.example'
    assert app.appRoles[0]['value'] == 'Reader'
    assert app.availableToOtherTenants is False

    role = session.get(DirectoryRole, 'tenant-c-role-1')
    assert role.displayName == 'tenant-c Global Reader'
    assert role.roleTemplateId == 'role-template-1'

    grant = session.get(OAuth2PermissionGrant, 'tenant-a-grant-1')
    assert grant.startTime.microsecond == 123000
    assert grant.expiryTime.microsecond == 123456

    session.close()


def test_incremental_delta_is_tenant_scoped(tmp_path):
    dbfile = str(tmp_path / 'roadrecon.db')
    dburl = 'sqlite:///' + dbfile

    graphs = {}
    for tenant in ('tenant-a', 'tenant-b', 'tenant-c'):
        graphs[tenant] = make_tenant_graph(tenant)
        run_collector(dburl, tenant, graphs[tenant])

    # Change only tenant A. Tenant B and C must remain untouched.
    graph_a = graphs['tenant-a']
    graph_a.set_delta('applications', values=[{
        'id': 'tenant-a-app-1',
        'appId': 'tenant-a-appid-1',
        'displayName': 'Tenant A Portal v2',
        'signInAudience': 'AzureADMultipleOrgs',
        'appRoles': [{
            'id': 'role-1',
            'displayName': 'Reader',
            'value': 'Reader',
            'isEnabled': True,
        }, {
            'id': 'role-2',
            'displayName': 'Writer',
            'value': 'Writer',
            'isEnabled': True,
        }],
    }, {
        'id': 'tenant-a-app-3',
        'appId': 'tenant-a-appid-3',
        'displayName': 'Tenant A New App',
    }], removed_ids=('tenant-a-app-2',))
    graph_a.set_delta('directoryRoles', values=[{
        'id': 'tenant-a-role-1',
        'displayName': 'Tenant A Global Administrator',
        'roleTemplateId': 'role-template-1',
    }])
    graph_a.set_delta('servicePrincipals', values=[])
    graph_a.set_delta('oauth2PermissionGrants', values=[])

    results = run_collector(dburl, 'tenant-a', graph_a)
    by_resource = {result.resource: result for result in results}
    assert by_resource['applications'].mode == 'delta'
    assert by_resource['applications'].updated == 1
    assert by_resource['applications'].added == 1
    assert by_resource['applications'].deleted == 1

    # The second run must use the delta link saved by the first run.
    assert any('$deltatoken=tenant-a-applications-v1' in call
               for call in graph_a.calls)

    engine = database.init(False, dburl=dburl)
    session = sessionmaker(bind=engine)()
    app1 = session.get(Application, 'tenant-a-app-1')
    assert app1.displayName == 'Tenant A Portal v2'
    assert len(app1.appRoles) == 2
    assert app1.availableToOtherTenants is True

    removed = session.get(Application, 'tenant-a-app-2')
    assert removed is not None
    assert removed.deletionTimestamp is not None
    assert session.get(Application, 'tenant-a-app-3') is not None

    # Other tenants were not changed by tenant A's delta.
    assert session.get(Application, 'tenant-b-app-1').displayName == 'tenant-b Portal'
    assert session.get(Application, 'tenant-c-app-1').displayName == 'tenant-c Portal'
    assert session.get(Application, 'tenant-b-app-2').deletionTimestamp is None

    state = session.get(CollectorState, ('tenant-a', 'applications'))
    assert 'tenant-a-applications-v' in state.deltaLink
    assert not state.deltaLink.endswith('tenant-a-applications-v1')
    assert session.get(
        CollectorState, ('tenant-b', 'applications')).deltaLink.endswith(
            'tenant-b-applications-v1')
    session.close()


def test_full_snapshot_prunes_only_ledgered_objects(tmp_path):
    dbfile = str(tmp_path / 'roadrecon.db')
    dburl = 'sqlite:///' + dbfile

    # Legacy data without ledger entries must survive a full new-collector run.
    engine = create_engine(dburl)
    Application.__table__.create(engine)
    session = sessionmaker(bind=engine)()
    session.add(Application(
        objectType='Application',
        objectId='legacy-app',
        displayName='Legacy application',
    ))
    session.commit()
    session.close()

    graph = make_tenant_graph('tenant-a')
    run_collector(dburl, 'tenant-a', graph)

    # A later full snapshot no longer contains app-2. App-2 is ledgered and
    # should be marked deleted; the legacy row was never ledgered and remains.
    graph.set_full('applications', [{
        'id': 'tenant-a-app-1',
        'appId': 'tenant-a-appid-1',
        'displayName': 'Tenant A Portal',
    }])
    run_collector(dburl, 'tenant-a', graph, full=True)

    engine = database.init(False, dburl=dburl)
    session = sessionmaker(bind=engine)()
    assert session.get(Application, 'legacy-app') is not None
    assert session.get(Application, 'tenant-a-app-1') is not None
    assert session.get(Application, 'tenant-a-app-2').deletionTimestamp is not None
    session.close()


def test_delta_pagination_advances_cursor_after_last_page(tmp_path):
    dbfile = str(tmp_path / 'roadrecon.db')
    dburl = 'sqlite:///' + dbfile
    graph = FakeGraph('tenant-a')
    graph.set_full('applications', [{
        'id': 'tenant-a-app-1',
        'appId': 'tenant-a-appid-1',
        'displayName': 'First page app',
    }])

    class PagedSession(FakeSession):
        def get(self, url, headers=None):
            if 'skiptoken=page2' in url:
                self.graph.calls.append(url)
                return FakeResponse({
                    'value': [{
                        'id': 'tenant-a-app-2',
                        'appId': 'tenant-a-appid-2',
                        'displayName': 'Second page app',
                    }],
                    '@odata.deltaLink': 'https://graph.microsoft.com/v1.0/applications/delta?$deltatoken=final',
                })
            if '/applications/delta' in url:
                self.graph.calls.append(url)
                return FakeResponse({
                    'value': [{
                        'id': 'tenant-a-app-1',
                        'appId': 'tenant-a-appid-1',
                        'displayName': 'First page app',
                    }],
                    '@odata.nextLink': 'https://graph.microsoft.com/v1.0/applications/delta?$skiptoken=page2',
                })
            return super().get(url, headers)

    engine = database.init(False, dburl=dburl)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    collector = AzureADRoleApplicationCollector(
        'tenant-a', session, graph_client=GraphClient(PagedSession(graph)))
    results = asyncio.run(collector.collect(resources=('applications',)))
    assert results[0].ok
    assert results[0].pages == 2
    assert results[0].itemCount == 2
    assert results[0].deltaLink.endswith('$deltatoken=final')
    assert session.get(Application, 'tenant-a-app-2') is not None
    session.close()


def test_expired_delta_cursor_falls_back_to_full_snapshot(tmp_path):
    dbfile = str(tmp_path / 'roadrecon.db')
    dburl = 'sqlite:///' + dbfile
    graph = make_tenant_graph('tenant-a')
    run_collector(dburl, 'tenant-a', graph)

    class ExpiredSession(FakeSession):
        failed = False

        def get(self, url, headers=None):
            if '$deltatoken=' in url and not self.failed:
                self.failed = True
                self.graph.calls.append(url)
                return FakeResponse({'error': 'expired'}, status=410)
            return super().get(url, headers)

    engine = database.init(False, dburl=dburl)
    session = sessionmaker(bind=engine)()
    collector = AzureADRoleApplicationCollector(
        'tenant-a', session,
        graph_client=GraphClient(ExpiredSession(graph), retries=0))
    results = asyncio.run(collector.collect(resources=('applications',)))
    assert results[0].ok
    assert results[0].mode == 'full'
    assert results[0].warnings
    assert session.get(Application, 'tenant-a-app-1') is not None
    state = session.get(CollectorState, ('tenant-a', 'applications'))
    assert state.deltaLink
    session.close()
