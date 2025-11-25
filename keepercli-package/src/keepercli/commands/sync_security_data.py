"""
Sync Security Data Command

This module provides CLI commands for synchronizing security audit data for Keeper records.
"""

import argparse
import itertools
import logging
from typing import Set

from keepersdk import security_data
from keepersdk.vault import vault_record

from . import base
from .. import api
from ..helpers import record_utils
from ..params import KeeperParams

logger = logging.getLogger(__name__)


def raise_parse_exception(message):
    """Raise a parse exception for argument parser errors."""
    raise base.ParseError(message)


def suppress_exit(*args):
    """Suppress parser exit and raise ParseError instead."""
    raise base.ParseError()


# Create argument parser for sync-security-data command
sync_security_data_parser = argparse.ArgumentParser(
    prog='sync-security-data',
    description='Sync security audit data for Keeper records'
)

record_name_help = (
    'Path or UID of record whose security data is to be updated. Multiple values allowed. '
    'Set to "@all" to update security data for all records.'
)

sync_security_data_parser.add_argument(
    'record',
    type=str,
    action='store',
    nargs="+",
    help=record_name_help
)

sync_security_data_parser.add_argument(
    '--force', '-f',
    action='store_true',
    help='force update of security data (ignore existing security data timestamp)'
)

sync_security_data_parser.add_argument(
    '--quiet', '-q',
    action='store_true',
    help='run command w/ minimal output'
)

sync_security_data_parser.error = raise_parse_exception
sync_security_data_parser.exit = suppress_exit


class SyncSecurityDataCommand(base.ArgparseCommand):
    """
    Command to synchronize security audit data for Keeper records.
    
    This command updates security data including:
    - Password strength scores
    - Breach watch status
    - Domain information
    - Passkey status
    """
    
    def __init__(self):
        super().__init__(sync_security_data_parser)
    
    def get_parser(self):
        """Get the argument parser for this command."""
        return sync_security_data_parser
    
    def execute(self, context: KeeperParams, **kwargs):
        """
        Execute the sync-security-data command.
        
        Args:
            context: KeeperParams instance with vault access
            **kwargs: Command arguments including:
                - record: List of record names/UIDs or "@all"
                - force: Force update flag
                - quiet: Quiet mode flag
        """
        # Check for enterprise key requirement
        if not context.vault:
            raise base.CommandError('sync-security-data', 'Vault not initialized. Please login first.')
        
        vault = context.vault
        auth_context = vault.keeper_auth.auth_context
        
        if not (auth_context.enterprise_ec_public_key or auth_context.enterprise_rsa_public_key):
            msg = 'Command not allowed -- This command is limited to enterprise users only.'
            raise base.CommandError('sync-security-data', msg)
        
        # Parse input records
        def parse_input_records() -> Set[str]:
            """Parse record names/UIDs from command arguments."""
            names = kwargs.get('record', [])
            do_all = '@all' in names
            
            if do_all:
                # Return all record UIDs from vault
                return set(r.record_uid for r in vault.vault_data.records())
            else:
                # Resolve each record name/pattern to UIDs
                return set(itertools.chain.from_iterable(
                    record_utils.resolve_records(n, context) for n in names
                ))
        
        # Parse parameters
        force_update = kwargs.get('force', False)
        quiet = kwargs.get('quiet', False)
        
        # Sync vault before processing
        vault.sync_requested = True
        vault.sync_down()
        
        # Load records
        try:
            record_uids = parse_input_records()
        except Exception as e:
            raise base.CommandError('sync-security-data', f'Error resolving records: {e}')
        
        if not record_uids:
            if not quiet:
                logger.info('No records found matching the specified criteria')
            return
        
        # Load record objects
        records = []
        for record_uid in record_uids:
            try:
                record = vault.vault_data.load_record(record_uid)
                if record and isinstance(record, (vault_record.PasswordRecord, vault_record.TypedRecord)):
                    records.append(record)
            except Exception as e:
                pass  # Skip records that can't be loaded
        
        # Filter records that need update
        should_update = lambda r: force_update or security_data.needs_security_audit(vault, r)
        recs_to_update = [r for r in records if should_update(r)]
        num_to_update = len(recs_to_update)
        
        # Update security audit data
        num_updated = security_data.update_security_audit_data(vault, recs_to_update, quiet=True)
        
        # Sync down after update to get latest data
        if num_updated:
            # Save reused password count if breach watch is available
            try:
                bwp = vault.breach_watch_plugin()
                if bwp and hasattr(bwp, 'breach_watch') and bwp.breach_watch:
                    # Count reused passwords
                    password_counts = {}
                    for record in vault.vault_data.records():
                        try:
                            rec_obj = vault.vault_data.load_record(record.record_uid)
                            if isinstance(rec_obj, (vault_record.PasswordRecord, vault_record.TypedRecord)):
                                password = rec_obj.extract_password()
                                if password:
                                    password_counts[password] = password_counts.get(password, 0) + 1
                        except Exception:
                            pass
                    
                    reused_count = sum(1 for count in password_counts.values() if count > 1)
                    if hasattr(vault, 'security_audit_plugin'):
                        sap = vault.security_audit_plugin()
                        if sap:
                            sap.set_reused_passwords(reused_count, 1)
            except Exception:
                pass  # Ignore reused password count errors
            
            vault.sync_requested = True
            vault.sync_down()
        
        # Output results
        if not quiet:
            if num_updated:
                logger.info(f'Updated security data for [{num_updated}] record(s)')
            elif not kwargs.get('suppress_no_op') and not num_to_update:
                logger.info('No records requiring security-data updates found')

