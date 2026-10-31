"""Trusted server operator bootstrap/recovery. No default accounts or public signup."""
import argparse
import getpass
import json
import sys

from auth import IdentityStore
from config import Settings


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    create = sub.add_parser('create-user')
    create.add_argument('username')
    create.add_argument('--role', choices=['admin', 'viewer'], default='viewer')
    reset = sub.add_parser('reset-password')
    reset.add_argument('username')
    disable = sub.add_parser('disable-user')
    disable.add_argument('username')
    enable = sub.add_parser('enable-user')
    enable.add_argument('username')
    collector = sub.add_parser('create-collector')
    collector.add_argument('host')
    revoke = sub.add_parser('revoke-collector')
    revoke.add_argument('id')
    sub.add_parser('list')
    args = parser.parse_args()
    settings = Settings()
    store = IdentityStore(settings.identity_db_path)
    store.initialize()
    try:
        if args.command in {'create-user', 'reset-password'}:
            if not sys.stdin.isatty():
                raise ValueError('Use an interactive terminal (docker compose exec, without -T) to enter a password securely')
            password = getpass.getpass('New password (15–128 characters): ')
            if password != getpass.getpass('Repeat password: '):
                raise ValueError('Passwords did not match')
            if args.command == 'create-user':
                store.create_user(args.username, password, args.role)
            else:
                store.update_user(args.username, password=password)
            print('Account saved. Password changes invalidate existing sessions.')
        elif args.command in {'disable-user', 'enable-user'}:
            store.update_user(args.username, enabled=args.command == 'enable-user')
            print('Account updated.')
        elif args.command == 'create-collector':
            result = store.create_collector(args.host)
            result['api_url'] = settings.public_origin or 'http://127.0.0.1:8000'
            print(json.dumps(result, indent=2))
            print('Save this config securely; the token cannot be retrieved again.', file=sys.stderr)
        elif args.command == 'revoke-collector':
            store.revoke_collector(args.id)
            print('Collector credential revoked.')
        else:
            print(json.dumps(store.inventory(), indent=2))
    except ValueError as exc:
        raise SystemExit(str(exc)) from None


if __name__ == '__main__':
    main()
