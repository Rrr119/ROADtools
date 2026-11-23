"""
CLI entry point for the incremental Entra role/application collector.

Examples::

    roadrecon rolegather -f .roadtools_auth
    roadrecon rolegather -d roadrecon.db --all
    roadrecon rolegather --full -t <tenant-id>
"""

import argparse
import asyncio
import json
import sys
import time

import aiohttp
from sqlalchemy.orm import sessionmaker

import roadtools.roadlib.metadef.database as database
from roadtools.roadlib.auth import Authentication
from roadtools.roadlib.metadef.database import Base
from roadtools.roadrecon.collector import (
    ALL_RESOURCES,
    DEFAULT_RESOURCES,
    GRAPH_BASE_URL,
    GRAPH_RESOURCE,
    AzureADRoleApplicationCollector,
    GraphTokenProvider,
)


def getargs(gather_parser):
    gather_parser.add_argument(
        '-d', '--database', action='store',
        help='Database file. Can be the local database name for SQLite, or an '
             'SQLAlchemy compatible URL. Default: roadrecon.db',
        default='roadrecon.db')
    gather_parser.add_argument(
        '-f', '--tokenfile', action='store',
        help='File to read credentials from obtained by roadrecon auth',
        default='.roadtools_auth')
    gather_parser.add_argument(
        '--tokens-stdin', action='store_true',
        help='Read tokens from stdin instead of from disk')
    gather_parser.add_argument(
        '-t', '--tenant', action='store',
        help='Tenant ID to gather, if this info is not stored in the token')
    gather_parser.add_argument(
        '-ua', '--user-agent', action='store',
        help='Custom user agent to use')
    gather_parser.add_argument(
        '--autotoken', action='store_true',
        help='Use the refresh token to request a Microsoft Graph token')
    gather_parser.add_argument(
        '--full', action='store_true',
        help='Ignore the stored delta cursor and perform a full snapshot')
    gather_parser.add_argument(
        '--incremental', dest='incremental', action='store_true', default=True,
        help='Use the stored delta cursor when available (default)')
    gather_parser.add_argument(
        '--no-incremental', dest='incremental', action='store_false',
        help='Alias for --full')
    gather_parser.add_argument(
        '--all', action='store_true',
        help='Also refresh role definitions, role assignments and application '
             'role assignments')
    gather_parser.add_argument(
        '--resource', action='append', dest='resources',
        choices=ALL_RESOURCES,
        help='Collect only the specified resource (repeatable)')
    gather_parser.add_argument(
        '--strict', action='store_true',
        help='Stop on the first Graph error instead of continuing with other '
             'resources')


def _read_token(args):
    if args.tokens_stdin:
        return json.loads(sys.stdin.read())
    with open(args.tokenfile, 'r') as infile:
        return json.load(infile)


def _database_url(path):
    return database.parse_db_argument(path)


def _tenant_from_token(token, args):
    if 'tenantId' in token:
        return token['tenantId']
    if args.tenant:
        return args.tenant
    try:
        _, tokendata = Authentication.parse_accesstoken(token['accessToken'])
        return tokendata.get('tid', 'myorganization')
    except Exception:
        return 'myorganization'


async def run(args, token):
    dburl = _database_url(args.database)
    # create_all is additive: it only creates missing tables, so existing
    # ROADrecon databases keep working and get the two collector tables.
    engine = database.init(False, dburl=dburl)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    tenant_id = _tenant_from_token(token, args)
    provider = GraphTokenProvider(
        token,
        client_id=token.get('_clientId'),
        user_agent=args.user_agent,
        tenant=tenant_id,
        resource=GRAPH_RESOURCE,
        refresh='refreshToken' in token,
    )

    resources = args.resources
    if resources:
        resources = list(resources)
    elif args.all:
        resources = ALL_RESOURCES
    else:
        resources = DEFAULT_RESOURCES

    results = []
    try:
        async with aiohttp.ClientSession() as http_session:
            collector = AzureADRoleApplicationCollector(
                tenant_id,
                session,
                http_session=http_session,
                headers=provider,
                base_url=GRAPH_BASE_URL,
            )
            results = await collector.collect(
                resources=resources,
                full=getattr(args, 'full', False) or not getattr(args, 'incremental', True),
                strict=args.strict,
            )
    finally:
        session.close()

    for result in results:
        status = 'ok' if result.ok else 'ERROR: %s' % result.error
        print(
            '{resource}: mode={mode} added={added} updated={updated} '
            'unchanged={unchanged} '
            'deleted={deleted} items={itemCount} pages={pages} {status}'.format(
                status=status, **result.__dict__))
        for warning in result.warnings:
            print('  warning: %s' % warning)
    return results


def main(args=None):
    if args is None:
        parser = argparse.ArgumentParser(
            add_help=True,
            description='ROADrecon - Incrementally gather Entra ID roles and applications',
            formatter_class=argparse.RawDescriptionHelpFormatter)
        getargs(parser)
        args = parser.parse_args()
        if len(sys.argv) < 2:
            parser.print_help()
            sys.exit(1)

    token = _read_token(args)
    if 'accessToken' not in token:
        print('No access token found in tokenfile')
        return

    try:
        _, tokendata = Authentication.parse_accesstoken(token['accessToken'])
    except Exception as exc:
        print('Could not parse access token: %s' % exc)
        return

    audience = tokendata.get('aud')
    if audience not in (
            'https://graph.microsoft.com',
            'https://graph.microsoft.com/',
            '00000003-0000-0000-c000-000000000000'):
        if args.autotoken and 'refreshToken' in token:
            auth = Authentication()
            token = auth.handle_autotoken(
                token, args=args, resource=GRAPH_RESOURCE)
        else:
            print('Wrong token audience, got %s but expected %s' % (
                audience, GRAPH_RESOURCE))
            print('Request a Graph token with: roadrecon auth -r msgraph')
            return

    seconds = time.perf_counter()
    results = asyncio.run(run(args, token))
    elapsed = time.perf_counter() - seconds
    errors = [result for result in results if not result.ok]
    print('ROADrecon rolegather executed in {0:0.2f} seconds ({1} resource(s), {2} error(s)).'.format(
        elapsed, len(results), len(errors)))
    if errors and args.strict:
        sys.exit(1)


if __name__ == '__main__':
    main()
