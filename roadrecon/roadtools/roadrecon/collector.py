"""
Incremental Microsoft Graph collector for Entra ID roles and applications.

The collector deliberately writes to the existing ROADrecon tables (the ones
used by ``roadrecon gather``) so existing databases and the GUI remain usable.
Only two additive bookkeeping tables are introduced:

* ``CollectorStates`` stores the per-tenant delta cursor.
* ``CollectorObjects`` stores which objects were seen for a tenant/resource.

The object ledger is important for two reasons:

* A first run against a database populated by the legacy AAD Graph collector
  must not prune objects that the new collector has never seen.
* Multiple tenants can share one database without one tenant pruning another
  tenant's objects.
"""

import asyncio
import datetime
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin

from roadtools.roadlib.metadef.database import (
    Application,
    AppRoleAssignment,
    CollectorObject,
    CollectorState,
    DirectoryRole,
    OAuth2PermissionGrant,
    RoleAssignment,
    RoleDefinition,
    ServicePrincipal,
)

GRAPH_RESOURCE = 'https://graph.microsoft.com'
GRAPH_BASE_URL = 'https://graph.microsoft.com/v1.0'
DEFAULT_PAGE_SIZE = 999
DEFAULT_RETRIES = 3
_MODEL_COLUMN_CACHE = {}


class GraphRequestError(Exception):
    """Raised when Microsoft Graph returns a non-success response."""

    def __init__(self, status, url, message=''):
        self.status = status
        self.url = url
        self.message = message
        super().__init__('Microsoft Graph returned HTTP %s for %s: %s' % (status, url, message))


@dataclass
class CollectionResult:
    """Outcome of collecting one resource for one tenant."""

    resource: str
    mode: str = 'full'
    added: int = 0
    updated: int = 0
    unchanged: int = 0
    deleted: int = 0
    pages: int = 0
    itemCount: int = 0
    deltaLink: Optional[str] = None
    error: Optional[str] = None
    warnings: list = field(default_factory=list)

    @property
    def ok(self):
        return self.error is None


def _utcnow():
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


def _model_columns(model):
    try:
        return _MODEL_COLUMN_CACHE[model]
    except KeyError:
        columns = {column.name for column in model.__table__.columns}
        _MODEL_COLUMN_CACHE[model] = columns
        return columns


def _copy_present(out, raw, source, target=None):
    if source in raw:
        out[target or source] = raw[source]


def _parse_graph_datetime(value):
    if not isinstance(value, str):
        return value
    try:
        parsed = datetime.datetime.fromisoformat(
            value[:-1] + '+00:00' if value.endswith('Z') else value)
        if parsed.tzinfo is not None:
            parsed = parsed.astimezone(
                datetime.timezone.utc).replace(tzinfo=None)
        return parsed
    except ValueError:
        return value


def _copy_time(out, raw, source, target=None):
    if source in raw:
        out[target or source] = _parse_graph_datetime(raw[source])


def _scope_list(raw):
    scopes = []
    for prop in ('directoryScopeId', 'appScopeId'):
        value = raw.get(prop)
        if value is not None and value not in scopes:
            scopes.append(value)
    return scopes


def map_directory_role(raw):
    out = {
        'objectType': 'DirectoryRole',
        'objectId': raw.get('id'),
    }
    _copy_time(out, raw, 'deletedDateTime', 'deletionTimestamp')
    _copy_present(out, raw, 'description')
    _copy_present(out, raw, 'displayName')
    _copy_present(out, raw, 'roleTemplateId')
    _copy_present(out, raw, 'cloudSecurityIdentifier')
    if 'isBuiltIn' in raw:
        out['isSystem'] = raw['isBuiltIn']
    if 'isEnabled' in raw:
        out['roleDisabled'] = not raw['isEnabled']
    return out


def map_application(raw):
    out = {
        'objectType': 'Application',
        'objectId': raw.get('id'),
    }
    _copy_time(out, raw, 'deletedDateTime', 'deletionTimestamp')
    for prop in (
            'appId', 'displayName', 'appRoles', 'identifierUris',
            'keyCredentials', 'passwordCredentials', 'requiredResourceAccess',
            'publisherDomain', 'groupMembershipClaims', 'optionalClaims',
            'samlMetadataUrl', 'tokenEncryptionKeyId', 'verifiedPublisher',
            'certification', 'disabledByMicrosoftStatus', 'tags',
            'isDeviceOnlyAuthSupported', 'parentalControlSettings'):
        _copy_present(out, raw, prop)

    sign_in_audience = raw.get('signInAudience')
    if sign_in_audience is not None:
        out['availableToOtherTenants'] = sign_in_audience != 'AzureADMyOrg'

    if 'isFallbackPublicClient' in raw:
        out['publicClient'] = raw['isFallbackPublicClient']
    elif isinstance(raw.get('publicClient'), dict):
        out['publicClient'] = True

    web = raw.get('web')
    if isinstance(web, dict):
        if 'redirectUris' in web:
            out['replyUrls'] = web['redirectUris']
        if 'homePageUrl' in web:
            out['homepage'] = web['homePageUrl']
        if 'homepageUrl' in web:
            out['homepage'] = web['homepageUrl']
        if 'logoutUrl' in web:
            out['logoutUrl'] = web['logoutUrl']
        implicit = web.get('implicitGrantSettings')
        if isinstance(implicit, dict):
            out['oauth2AllowImplicitFlow'] = bool(implicit.get('enableAccessTokenIssuance'))
            out['oauth2AllowIdTokenImplicitFlow'] = bool(implicit.get('enableIdTokenIssuance'))

    spa = raw.get('spa')
    if isinstance(spa, dict) and 'redirectUris' in spa and 'replyUrls' not in out:
        out['replyUrls'] = spa['redirectUris']

    info = raw.get('info')
    if isinstance(info, dict):
        out['informationalUrls'] = info

    api = raw.get('api')
    if isinstance(api, dict):
        if 'oauth2PermissionScopes' in api:
            out['oauth2Permissions'] = api['oauth2PermissionScopes']

    return out


def map_service_principal(raw):
    out = {
        'objectType': 'ServicePrincipal',
        'objectId': raw.get('id'),
    }
    _copy_time(out, raw, 'deletedDateTime', 'deletionTimestamp')
    for prop in (
            'accountEnabled', 'addIns', 'alternativeNames', 'appCategory',
            'appDisplayName', 'appId', 'applicationTemplateId', 'appMetadata',
            'appOwnerTenantId', 'appRoleAssignmentRequired', 'appRoles',
            'authenticationPolicy', 'disabledByMicrosoftStatus', 'displayName',
            'errorUrl', 'homepage', 'informationalUrls', 'keyCredentials',
            'logoutUrl', 'managedIdentityResourceId', 'microsoftFirstParty',
            'notificationEmailAddresses', 'passwordCredentials',
            'preferredSingleSignOnMode',
            'preferredTokenSigningKeyThumbprint', 'publisherName',
            'replyUrls', 'samlMetadataUrl', 'samlSingleSignOnSettings',
            'servicePrincipalNames', 'tags', 'tokenEncryptionKeyId',
            'servicePrincipalType', 'useCustomTokenSigningKey',
            'verifiedPublisher'):
        _copy_present(out, raw, prop)

    _copy_time(out, raw, 'preferredTokenSigningKeyEndDateTime')
    if 'appDisplayName' not in out and 'displayName' in raw:
        out['appDisplayName'] = raw['displayName']
    for prop in ('oauth2PermissionScopes', 'publishedPermissionScopes', 'oauth2Permissions'):
        if prop in raw:
            out['oauth2Permissions'] = raw[prop]
            break
    return out


def map_oauth2_permission_grant(raw):
    out = {
        'objectType': 'OAuth2PermissionGrant',
        'objectId': raw.get('id'),
    }
    _copy_time(out, raw, 'deletedDateTime', 'deletionTimestamp')
    _copy_time(out, raw, 'startTime')
    _copy_time(out, raw, 'expiryTime')
    for prop in (
            'clientId', 'consentType', 'principalId', 'resourceId', 'scope'):
        _copy_present(out, raw, prop)
    return out


def map_role_definition(raw):
    out = {
        'objectType': 'RoleDefinition',
        'objectId': raw.get('id'),
    }
    _copy_time(out, raw, 'deletedDateTime', 'deletionTimestamp')
    for prop in (
            'description', 'displayName', 'isBuiltIn', 'isEnabled',
            'resourceScopes', 'rolePermissions', 'templateId', 'version'):
        _copy_present(out, raw, prop)
    return out


def map_role_assignment(raw):
    out = {
        'id': raw.get('id'),
    }
    _copy_present(out, raw, 'principalId')
    _copy_present(out, raw, 'roleDefinitionId')
    scopes = _scope_list(raw)
    if scopes:
        out['resourceScopes'] = scopes
    return out


def map_app_role_assignment(raw):
    out = {
        'objectType': 'AppRoleAssignment',
        'objectId': raw.get('id'),
        'id': raw.get('id'),
    }
    _copy_time(out, raw, 'deletedDateTime', 'deletionTimestamp')
    _copy_time(out, raw, 'creationTimestamp')
    for prop in (
            'appRoleId', 'principalDisplayName',
            'principalId', 'principalType', 'resourceDisplayName',
            'resourceId'):
        _copy_present(out, raw, prop)
    return out


class ResourceSpec:
    """Description of how one Graph resource maps to one ROADrecon table."""

    def __init__(self, name, endpoint, model, mapper, primary_key='objectId',
                 supports_delta=True, list_endpoint=None):
        self.name = name
        self.endpoint = endpoint
        self.model = model
        self.mapper = mapper
        self.primary_key = primary_key
        self.supports_delta = supports_delta
        self.list_endpoint = list_endpoint or endpoint


DEFAULT_RESOURCES = (
    'directoryRoles',
    'applications',
    'servicePrincipals',
    'oauth2PermissionGrants',
)

EXTENDED_RESOURCES = (
    'roleDefinitions',
    'roleAssignments',
    'appRoleAssignments',
)

ALL_RESOURCES = DEFAULT_RESOURCES + EXTENDED_RESOURCES


RESOURCE_SPECS = {
    'directoryRoles': ResourceSpec(
        'directoryRoles', 'directoryRoles', DirectoryRole, map_directory_role),
    'applications': ResourceSpec(
        'applications', 'applications', Application, map_application),
    'servicePrincipals': ResourceSpec(
        'servicePrincipals', 'servicePrincipals', ServicePrincipal, map_service_principal),
    'oauth2PermissionGrants': ResourceSpec(
        'oauth2PermissionGrants', 'oauth2PermissionGrants',
        OAuth2PermissionGrant, map_oauth2_permission_grant),
    'roleDefinitions': ResourceSpec(
        'roleDefinitions', 'roleManagement/directory/roleDefinitions',
        RoleDefinition, map_role_definition, supports_delta=False),
    'roleAssignments': ResourceSpec(
        'roleAssignments', 'roleManagement/directory/roleAssignments',
        RoleAssignment, map_role_assignment, primary_key='id',
        supports_delta=False),
    'appRoleAssignments': ResourceSpec(
        'appRoleAssignments', None, AppRoleAssignment, map_app_role_assignment,
        supports_delta=False),
}

COLLECTORS = RESOURCE_SPECS


class GraphTokenProvider:
    """
    Callable header provider that refreshes a Graph token when possible.

    ``token`` uses the same dict format as ``roadrecon auth`` writes.
    """

    def __init__(self, token, client_id=None, user_agent=None, tenant=None,
                 resource=GRAPH_RESOURCE, refresh=True):
        self.token = dict(token)
        self.client_id = client_id
        self.user_agent = user_agent
        self.tenant = tenant
        self.resource = resource
        self.refresh = refresh
        self.expiretime = self._parse_expiry(self.token)

    @staticmethod
    def _parse_expiry(token):
        expires = token.get('expiresOn')
        if expires:
            try:
                return time.mktime(time.strptime(expires.split('.')[0], '%Y-%m-%d %H:%M:%S'))
            except ValueError:
                pass
        access_token = token.get('accessToken')
        if access_token:
            try:
                _, tokendata = _parse_accesstoken(access_token)
                return float(tokendata.get('exp', time.time() + 3600))
            except Exception:
                pass
        return time.time() + 3600

    def _refresh(self):
        if not self.refresh or 'refreshToken' not in self.token:
            return
        from roadtools.roadlib.auth import Authentication

        auth = Authentication()
        auth.client_id = self.client_id or self.token.get('_clientId')
        auth.tenant = self.tenant or self.token.get('tenantId', 'myorganization')
        auth.tokendata = self.token
        if self.user_agent:
            auth.set_user_agent(self.user_agent)
        self.token = auth.handle_autotoken(self.token, resource=self.resource)
        self.expiretime = self._parse_expiry(self.token)

    def __call__(self):
        if time.time() > self.expiretime - 300:
            self._refresh()
        return {
            'Authorization': '%s %s' % (
                self.token.get('tokenType', 'Bearer'), self.token['accessToken'])
        }


def _parse_accesstoken(access_token):
    from roadtools.roadlib.auth import Authentication
    return Authentication.parse_accesstoken(access_token)


class GraphClient:
    """Small async Microsoft Graph client with paging-friendly JSON calls."""

    def __init__(self, session, headers=None, base_url=GRAPH_BASE_URL,
                 retries=DEFAULT_RETRIES, sleep=asyncio.sleep):
        self.session = session
        self.headers = headers or {}
        self.base_url = base_url.rstrip('/')
        self.retries = retries
        self.sleep = sleep

    def _headers(self):
        if callable(self.headers):
            return self.headers()
        return self.headers

    async def get_json(self, url):
        last_error = None
        for attempt in range(self.retries + 1):
            try:
                async with self.session.get(url, headers=self._headers()) as response:
                    status = response.status
                    if 200 <= status < 300:
                        return await response.json()
                    body = await response.text()
                    if status == 429 or 500 <= status < 600:
                        last_error = GraphRequestError(status, url, body[:500])
                        if attempt < self.retries:
                            retry_after = response.headers.get('Retry-After')
                            if retry_after:
                                try:
                                    delay = float(retry_after)
                                except ValueError:
                                    delay = 2 ** attempt
                            else:
                                delay = 2 ** attempt
                            await self.sleep(min(delay, 30))
                            continue
                    raise GraphRequestError(status, url, body[:500])
            except GraphRequestError:
                raise
            except Exception as exc:
                last_error = exc
                if attempt >= self.retries:
                    break
                await self.sleep(2 ** attempt)
        if isinstance(last_error, GraphRequestError):
            raise last_error
        raise GraphRequestError(0, url, str(last_error))


class AzureADRoleApplicationCollector:
    """
    Collect Entra ID directory roles and application objects incrementally.

    By default the four delta-capable resources are collected:
    ``directoryRoles``, ``applications``, ``servicePrincipals`` and
    ``oauth2PermissionGrants``. Use ``resources=ALL_RESOURCES`` (or the
    ``--all`` CLI flag) to additionally refresh role definitions, directory
    role assignments and application role assignments.
    """

    def __init__(self, tenant_id, session, graph_client=None, http_session=None,
                 headers=None, base_url=GRAPH_BASE_URL):
        self.tenant_id = tenant_id
        self.session = session
        self.ensure_schema()
        if graph_client is None:
            if http_session is None:
                raise ValueError('either graph_client or http_session is required')
            graph_client = GraphClient(
                http_session, headers=headers, base_url=base_url)
        self.graph = graph_client

    def ensure_schema(self):
        """
        Create only the additive collector tables if they are missing.

        This keeps library use compatible with databases created by older
        ROADrecon versions.
        """
        try:
            bind = self.session.get_bind()
        except Exception:
            return
        CollectorState.__table__.create(bind, checkfirst=True)
        CollectorObject.__table__.create(bind, checkfirst=True)

    @staticmethod
    def _id_of(raw):
        return raw.get('id') or raw.get('objectId')

    def _state(self, resource):
        return self.session.get(CollectorState, (self.tenant_id, resource))

    def _get_or_create_state(self, resource):
        state = self._state(resource)
        if state is None:
            state = CollectorState(tenantId=self.tenant_id, resource=resource)
            self.session.add(state)
        return state

    def _ledger(self, resource, object_id):
        return self.session.get(
            CollectorObject, (self.tenant_id, resource, object_id))

    def _mark_seen(self, resource, object_id):
        ledger = self._ledger(resource, object_id)
        if ledger is None:
            ledger = CollectorObject(
                tenantId=self.tenant_id,
                resource=resource,
                objectId=object_id)
            self.session.add(ledger)
        ledger.lastSeen = _utcnow()
        ledger.deleted = False

    def _mark_deleted(self, spec, object_id):
        """Mark a removed object deleted, using the existing schema semantics."""
        ledger = self._ledger(spec.name, object_id)
        if ledger is None:
            ledger = CollectorObject(
                tenantId=self.tenant_id,
                resource=spec.name,
                objectId=object_id)
            self.session.add(ledger)
        ledger.lastSeen = _utcnow()
        ledger.deleted = True

        obj = self.session.get(spec.model, object_id)
        if obj is None:
            return False
        columns = _model_columns(spec.model)
        if 'deletionTimestamp' in columns:
            obj.deletionTimestamp = _utcnow()
        elif 'deletedDateTime' in columns:
            obj.deletedDateTime = _utcnow()
        else:
            self.session.delete(obj)
        return True

    def _apply(self, spec, raw):
        object_id = self._id_of(raw)
        if not object_id:
            return None
        data = spec.mapper(raw)
        data = {key: value for key, value in data.items()
                if key in _model_columns(spec.model)}
        if not data.get(spec.primary_key):
            return None

        obj = self.session.get(spec.model, data[spec.primary_key])
        if obj is None:
            self.session.add(spec.model(**data))
            change = 'added'
        else:
            changed = False
            for key, value in data.items():
                if getattr(obj, key) != value:
                    changed = True
                setattr(obj, key, value)
            # A delta change can resurrect an object that we previously
            # soft-deleted. The new live payload has no deletion timestamp.
            if 'deletionTimestamp' not in data and 'deletionTimestamp' in _model_columns(spec.model):
                if obj.deletionTimestamp is not None:
                    changed = True
                obj.deletionTimestamp = None
            if 'deletedDateTime' not in data and 'deletedDateTime' in _model_columns(spec.model):
                if obj.deletedDateTime is not None:
                    changed = True
                obj.deletedDateTime = None
            change = 'updated' if changed else 'unchanged'
        self._mark_seen(spec.name, object_id)
        return change

    def _prune_missing(self, spec, seen):
        """
        Remove objects previously collected by this collector but absent from
        a completed full snapshot.

        Only ledgered objects are considered, so legacy AAD Graph data is never
        touched on the first incremental run.
        """
        query = self.session.query(CollectorObject).filter(
            CollectorObject.tenantId == self.tenant_id,
            CollectorObject.resource == spec.name,
            CollectorObject.deleted != True)  # noqa: E712 - SQL semantics
        # Filter in Python rather than emitting a huge NOT IN (...) clause.
        # Large tenants can easily exceed SQLite's bound-parameter limit.
        stale = [ledger for ledger in query.all()
                 if ledger.objectId not in seen]
        deleted = 0
        for ledger in stale:
            if self._mark_deleted(spec, ledger.objectId):
                deleted += 1
        return deleted

    @staticmethod
    def _initial_url(graph, spec, delta_link=None, page_size=DEFAULT_PAGE_SIZE):
        if delta_link:
            return delta_link
        if spec.supports_delta:
            return '%s/%s/delta?$top=%s' % (graph.base_url, spec.endpoint, page_size)
        return '%s/%s?$top=%s' % (graph.base_url, spec.list_endpoint, page_size)

    async def _walk(self, spec, start_url, result, seen):
        url = start_url
        delta_link = None
        while url:
            data = await self.graph.get_json(url)
            result.pages += 1
            for raw in data.get('value', []):
                object_id = self._id_of(raw)
                if '@removed' in raw:
                    if object_id and self._mark_deleted(spec, object_id):
                        result.deleted += 1
                    continue
                if not object_id:
                    continue
                change = self._apply(spec, raw)
                if change == 'added':
                    result.added += 1
                elif change == 'updated':
                    result.updated += 1
                elif change == 'unchanged':
                    result.unchanged += 1
                seen.add(object_id)
            next_link = data.get('@odata.nextLink')
            if next_link:
                url = urljoin(url, next_link)
            else:
                url = None
                if data.get('@odata.deltaLink'):
                    delta_link = data['@odata.deltaLink']
        result.deltaLink = delta_link
        result.itemCount = len(seen)
        return delta_link

    async def _collect_resource(self, name, full=False, strict=False):
        spec = RESOURCE_SPECS[name]
        result = CollectionResult(resource=name)
        state = self._get_or_create_state(name)

        delta_link = None if full else state.deltaLink
        delta_mode = bool(delta_link) and spec.supports_delta
        result.mode = 'delta' if delta_mode else 'full'
        seen = set()

        try:
            try:
                await self._walk(
                    spec,
                    self._initial_url(self.graph, spec, delta_link=delta_link),
                    result,
                    seen,
                )
            except GraphRequestError as exc:
                # Some clouds/tenants do not expose a delta function for one
                # of the resources, and delta links can expire. Fall back to a
                # fresh full snapshot once.
                if (spec.supports_delta and
                        exc.status in (400, 404, 405, 410, 501)):
                    result.warnings.append(
                        'delta endpoint/cursor unavailable (%s), using full snapshot'
                        % exc.status)
                    result.mode = 'full'
                    result.added = 0
                    result.updated = 0
                    result.unchanged = 0
                    result.deleted = 0
                    result.pages = 0
                    seen.clear()
                    await self._walk(
                        spec,
                        self._initial_url(self.graph, spec),
                        result,
                        seen,
                    )
                else:
                    raise

            # A delta response only reports changed/removed objects. A full
            # snapshot can safely prune only objects this collector has seen
            # before (the ledger), never legacy data from other collectors.
            if result.mode == 'full':
                result.deleted += self._prune_missing(spec, seen)

            now = _utcnow()
            if spec.supports_delta:
                # If a full run did not produce a new delta link, do not keep
                # an older cursor: the next run must perform a full snapshot.
                state.deltaLink = result.deltaLink
            else:
                state.deltaLink = None
            state.lastSuccessfulRun = now
            state.lastRun = now
            state.itemCount = len(seen)
            state.fullSyncCompleted = result.mode == 'full' or not spec.supports_delta
            self.session.commit()
        except Exception as exc:
            result.error = str(exc)
            # Do not persist a half-finished page set. The previous delta
            # cursor is still valid and the next run will replay the changes.
            self.session.rollback()
            if strict:
                raise
        return result

    async def _collect_app_role_assignments(self, full=False, strict=False):
        """
        Enumerate assignments through the service principals known for this
        tenant. Graph does not expose a tenant-wide appRoleAssignments delta.
        """
        spec = RESOURCE_SPECS['appRoleAssignments']
        result = CollectionResult(resource=spec.name, mode='full')
        state = self._get_or_create_state(spec.name)
        seen = set()

        principals = self.session.query(CollectorObject).filter(
            CollectorObject.tenantId == self.tenant_id,
            CollectorObject.resource == 'servicePrincipals',
            CollectorObject.deleted != True).all()  # noqa: E712
        if not principals:
            # Compatibility path for objects collected by the legacy AAD
            # Graph collector, which has no ledger entries.
            principals = self.session.query(ServicePrincipal.objectId).all()

        try:
            for principal in principals:
                for link in ('appRoleAssignedTo', 'appRoleAssignments'):
                    url = '%s/servicePrincipals/%s/%s?$top=%s' % (
                        self.graph.base_url, principal.objectId, link,
                        DEFAULT_PAGE_SIZE)
                    while url:
                        data = await self.graph.get_json(url)
                        result.pages += 1
                        for raw in data.get('value', []):
                            object_id = self._id_of(raw)
                            if not object_id:
                                continue
                            change = self._apply(spec, raw)
                            if change == 'added':
                                result.added += 1
                            elif change == 'updated':
                                result.updated += 1
                            elif change == 'unchanged':
                                result.unchanged += 1
                            seen.add(object_id)
                        next_link = data.get('@odata.nextLink')
                        url = urljoin(url, next_link) if next_link else None

            result.itemCount = len(seen)
            result.deleted += self._prune_missing(spec, seen)
            now = _utcnow()
            state.lastSuccessfulRun = now
            state.lastRun = now
            state.itemCount = len(seen)
            state.fullSyncCompleted = True
            state.deltaLink = None
            self.session.commit()
        except Exception as exc:
            result.error = str(exc)
            self.session.rollback()
            if strict:
                raise
        return result

    async def collect(self, resources=None, full=False, strict=False,
                      incremental=None):
        """
        Run the collector and return one :class:`CollectionResult` per
        resource. Resources are intentionally processed sequentially because
        they share one database session.
        """
        if resources is None:
            resources = DEFAULT_RESOURCES
        elif resources == 'all' or resources == ALL_RESOURCES:
            resources = ALL_RESOURCES
        if incremental is False:
            full = True

        results = []
        for name in resources:
            if name not in RESOURCE_SPECS:
                raise ValueError('unknown collector resource: %s' % name)
            if name == 'appRoleAssignments':
                result = await self._collect_app_role_assignments(
                    full=full, strict=strict)
            else:
                result = await self._collect_resource(
                    name, full=full, strict=strict)
            results.append(result)
        return results

    async def collect_roles(self, full=False, strict=False, incremental=None):
        """Collect directory roles (the delta-capable role objects)."""
        return await self.collect(
            resources=('directoryRoles',), full=full, strict=strict,
            incremental=incremental)

    async def collect_applications(self, full=False, strict=False,
                                   incremental=None):
        """Collect applications, service principals and OAuth2 grants."""
        return await self.collect(
            resources=('applications', 'servicePrincipals',
                       'oauth2PermissionGrants'),
            full=full,
            strict=strict,
            incremental=incremental,
        )

    async def collect_all(self, full=False, strict=False, incremental=None):
        """Collect every supported resource, including role assignments."""
        return await self.collect(
            resources=ALL_RESOURCES, full=full, strict=strict,
            incremental=incremental)


# Friendly aliases used by callers/tests.
RoleApplicationCollector = AzureADRoleApplicationCollector
AADRoleApplicationCollector = AzureADRoleApplicationCollector
GraphRoleApplicationCollector = AzureADRoleApplicationCollector
RoleAndApplicationCollector = AzureADRoleApplicationCollector
Collector = AzureADRoleApplicationCollector


def collect(tenant_id, session, http_session=None, graph_client=None,
            headers=None, resources=None, full=False, strict=False,
            base_url=GRAPH_BASE_URL, incremental=None):
    """Synchronous convenience wrapper around the async collector."""
    collector = AzureADRoleApplicationCollector(
        tenant_id,
        session,
        graph_client=graph_client,
        http_session=http_session,
        headers=headers,
        base_url=base_url,
    )
    return asyncio.run(collector.collect(
        resources=resources, full=full, strict=strict,
        incremental=incremental))


def collect_roles_and_applications(*args, **kwargs):
    """Alias with an explicit, descriptive name."""
    return collect(*args, **kwargs)


def collect_roles(tenant_id, session, http_session=None, graph_client=None,
                  headers=None, full=False, strict=False,
                  base_url=GRAPH_BASE_URL, incremental=None):
    collector = AzureADRoleApplicationCollector(
        tenant_id, session, graph_client=graph_client,
        http_session=http_session, headers=headers, base_url=base_url)
    return asyncio.run(collector.collect_roles(
        full=full, strict=strict, incremental=incremental))


def collect_applications(tenant_id, session, http_session=None,
                         graph_client=None, headers=None, full=False,
                         strict=False, base_url=GRAPH_BASE_URL,
                         incremental=None):
    collector = AzureADRoleApplicationCollector(
        tenant_id, session, graph_client=graph_client,
        http_session=http_session, headers=headers, base_url=base_url)
    return asyncio.run(collector.collect_applications(
        full=full, strict=strict, incremental=incremental))


def collect_all(tenant_id, session, http_session=None, graph_client=None,
                headers=None, full=False, strict=False,
                base_url=GRAPH_BASE_URL, incremental=None):
    collector = AzureADRoleApplicationCollector(
        tenant_id, session, graph_client=graph_client,
        http_session=http_session, headers=headers, base_url=base_url)
    return asyncio.run(collector.collect_all(
        full=full, strict=strict, incremental=incremental))
