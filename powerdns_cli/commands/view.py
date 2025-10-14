"""
A Click-based CLI module for managing DNS views in PowerDNS.
This module provides commands for managing DNS views,
which allow for zone access control and segmentation.
Commands:
    add: Adds a DNS zone to a view, creating the view if it does not exist.
    delete: Removes a DNS zone from a view.
    export: Exports the configuration of a single view.
    import: Imports views and their zone memberships from a file.
    list: Lists all views and their configurations.
    update: Updates a view to include a specified DNS zone.
    spec: Opens the view API specification in the browser.
"""

from typing import NoReturn, TextIO

import click

from ..utils import main as utils
from ..utils.validation import DefaultCommand, powerdns_zone


@click.group()
def view():
    """Configure views, which limit zone access based on IPs."""


@view.command(
    "add",
    cls=DefaultCommand,
    context_settings={"auto_envvar_prefix": "POWERDNS_CLI"},
    no_args_is_help=True,
)
@click.argument("view_id", type=click.STRING, metavar="view")
@powerdns_zone
@click.pass_context
def view_add(ctx: click.Context, view_id: str, dns_zone: str, **kwargs) -> NoReturn:
    """Add a zone to a view, creates the view if it does not exist."""
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/views/{view_id}"
    view_content = utils.http_get(uri, ctx)
    if view_content.status_code == 200 and dns_zone in view_content.json()["zones"]:
        ctx.obj.logger.info(f"{dns_zone} is already in {view_id}.")
        utils.exit_action(ctx, success=True, message=f"{dns_zone} already in {view_id}.")
    else:
        ctx.obj.logger.info(f"Adding {dns_zone} to {view_id}.")
        payload = {"name": f"{dns_zone}"}
        r = utils.http_post(uri, ctx, payload=payload)
        if r.status_code == 204:
            ctx.obj.logger.info(f"Successfully added {dns_zone} to {view_id}.")
            utils.exit_action(
                ctx, success=True, message=f"Added {dns_zone} to {view_id}.", response=r
            )
        else:
            ctx.obj.logger.error(f"Failed to add {dns_zone} to {view_id}.")
            utils.exit_action(
                ctx, success=False, message=f"Failed to add {dns_zone} to {view_id}.", response=r
            )


@view.command(
    "delete",
    cls=DefaultCommand,
    context_settings={"auto_envvar_prefix": "POWERDNS_CLI"},
    no_args_is_help=True,
)
@click.argument("view_id", type=click.STRING, metavar="view")
@powerdns_zone
@click.pass_context
def view_delete(ctx: click.Context, view_id: str, dns_zone: str, **kwargs) -> NoReturn:
    """Deletes a DNS zone from a view."""
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/views/{view_id}"
    view_content = utils.http_get(uri, ctx)
    if view_content.status_code == 200 and dns_zone not in view_content.json()["zones"]:
        ctx.obj.logger.info(f"Zone {dns_zone} is not in {view_id}.")
        utils.exit_action(ctx, success=True, message=f"Zone {dns_zone} is not in {view_id}.")
    elif view_content.status_code == 404:
        ctx.obj.logger.info(f"View {view_id} is absent.")
        utils.exit_action(ctx, success=True, message=f"View {view_id} is already absent.")
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/views/{view_id}/{dns_zone}"
    ctx.obj.logger.info(f"Attempting to delete {dns_zone} from {view_id} at {uri}.")
    r = utils.http_delete(uri, ctx)
    if r.status_code == 204:
        ctx.obj.logger.info(f"Successfully deleted {dns_zone} from {view_id}.")
        utils.exit_action(
            ctx, success=True, message=f"Deleted {dns_zone} from {view_id}.", response=r
        )
    else:
        ctx.obj.logger.error(f"Failed to delete {dns_zone} from {view_id}.")
        utils.exit_action(
            ctx, success=False, message=f"Failed to delete {dns_zone} from {view_id}.", response=r
        )


@view.command(
    "export",
    cls=DefaultCommand,
    context_settings={"auto_envvar_prefix": "POWERDNS_CLI"},
    no_args_is_help=True,
)
@click.argument("view_id", type=click.STRING, metavar="view")
@click.pass_context
def view_export(ctx, view_id, **kwargs):
    """
    Exports a single view for its configured zones.
    """
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/views/{view_id}"
    utils.show_setting(ctx, uri, "view", "export")


@view.command(
    "import",
    cls=DefaultCommand,
    context_settings={"auto_envvar_prefix": "POWERDNS_CLI"},
    no_args_is_help=True,
)
@click.argument("file", type=click.File())
@click.option(
    "--replace",
    type=click.BOOL,
    is_flag=True,
    help="Replace all view settings with new ones.",
)
@click.option("--ignore-errors", is_flag=True, help="Continue import even when requests fail.")
@click.pass_context
def view_import(
    ctx: click.Context, file: TextIO, replace: bool, ignore_errors: bool, **kwargs
) -> NoReturn:
    """Imports views and their contents into the server.
    File format:
    [{"view_name":["zone_name"]}]
    """
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/views"
    ctx.obj.logger.info("Importing views from file.")
    settings = utils.extract_file(ctx, file)
    if not validate_view_import(ctx, settings):
        ctx.obj.logger.error("Invalid view structure provided.")
        utils.exit_action(
            ctx,
            success=False,
            message="Views must adhere to the following structure: [{'view1':['example.org']}].",
        )
    restructured_settings = reformat_view_imports(ctx, settings)
    upstream_settings = get_upstream_views(ctx, uri)
    if replace and upstream_settings == restructured_settings:
        ctx.obj.logger.info("Requested views are already present.")
        utils.exit_action(ctx, success=True, message="Requested views are already present.")
    if not replace and all(
        is_zone_in_view(ctx, view_item, upstream_settings) for view_item in restructured_settings
    ):
        ctx.obj.logger.info("Requested views are already present.")
        utils.exit_action(ctx, success=True, message="Requested views are already present.")
    if replace and upstream_settings:
        ctx.obj.logger.info("Replacing existing views with new settings.")
        replace_view_import(uri, ctx, restructured_settings, upstream_settings, ignore_errors)
    else:
        ctx.obj.logger.info("Adding new views.")
        add_view_import(uri, ctx, restructured_settings, ignore_errors)
    ctx.obj.logger.info("Successfully imported views from file.")
    utils.exit_action(ctx, success=True, message="Successfully imported views from file.")


@view.command(
    "list",
    cls=DefaultCommand,
    context_settings={"auto_envvar_prefix": "POWERDNS_CLI"},
)
@click.pass_context
def view_list(ctx, **kwargs):
    """
    Shows all views and their configuration as a list.
    """
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/views"
    utils.show_setting(ctx, uri, "view", "list")


@view.command("spec")
def view_spec():
    """Open the view specification on https://redocly.github.io."""
    utils.open_spec("view")


@view.command(
    "update",
    cls=DefaultCommand,
    context_settings={"auto_envvar_prefix": "POWERDNS_CLI"},
    no_args_is_help=True,
)
@click.pass_context
@click.argument("view_id", type=click.STRING, metavar="view")
@powerdns_zone
def view_update(ctx: click.Context, view_id: str, dns_zone: str, **kwargs):
    """Update a view to contain the given zone."""
    ctx.forward(view_add)


def add_view_import(
    uri: str, ctx: click.Context, settings: list[dict], ignore_errors: bool
) -> None:
    """
    Import views from settings configuration.
    Args:
        uri: The connection string.
        ctx: Click context object for CLI operations.
        settings: List of view configuration dictionaries, each containing 'name' and 'views' keys.
        ignore_errors: Whether to continue processing if errors occur.
    """
    views_to_add = [
        {"name": view_entry["name"], "view": view_item}
        for view_entry in settings
        for view_item in view_entry["views"]
    ]
    if not views_to_add:
        ctx.obj.logger.info("No views to add.")
        return
    ctx.obj.logger.info(f"Adding {len(views_to_add)} view(s).")
    add_views(views_to_add, uri, ctx, continue_on_error=ignore_errors)
    ctx.obj.logger.info("Successfully added views.")


def replace_view_import(
    uri: str,
    ctx: click.Context,
    settings: list[dict],
    upstream_settings: list[dict],
    ignore_errors: bool,
) -> NoReturn:
    """
    Replace views by comparing current settings with upstream settings.
    This function performs a differential update:
    - Deletes views that exist in upstream but not in current settings.
    - Adds new views that exist in current but not in upstream settings.
    - For matching view names, adds/removes individual views based on set difference.
    Args:
        uri: Database URI or connection string.
        ctx: Click context object for CLI operations.
        settings: Current view configuration (target state).
        upstream_settings: Previous view configuration (current state).
        ignore_errors: Whether to continue processing if errors occur.
    """
    views_to_add = []
    views_to_delete = []
    ctx.obj.logger.info("Calculating view differences for replacement.")
    for old_view in upstream_settings:
        if old_view["name"] not in [viewset["name"] for viewset in settings]:
            for item in old_view["views"]:
                views_to_delete.append({"name": old_view["name"], "view": item})
            ctx.obj.logger.info(f"View {old_view['name']} marked for complete deletion.")
            continue
        for new_view in settings:
            if old_view["name"] == new_view["name"]:
                for item in new_view["views"].difference(old_view["views"]):
                    views_to_add.append({"name": old_view["name"], "view": item})
                    ctx.obj.logger.info(f"View {item} in {old_view['name']} marked for addition.")
                for item in old_view["views"].difference(new_view["views"]):
                    views_to_delete.append({"name": old_view["name"], "view": item})
                    ctx.obj.logger.info(f"View {item} in {old_view['name']} marked for deletion.")
    for new_view in settings:
        if new_view["name"] not in [viewset["name"] for viewset in upstream_settings]:
            for item in new_view["views"]:
                views_to_add.append({"name": new_view["name"], "view": item})
                ctx.obj.logger.info(f"View {item} in {new_view['name']} marked for addition.")
    if views_to_add:
        ctx.obj.logger.info(f"Adding {len(views_to_add)} view(s).")
        add_views(views_to_add, uri, ctx, continue_on_error=ignore_errors)
    if views_to_delete:
        ctx.obj.logger.info(f"Deleting {len(views_to_delete)} view(s).")
        delete_views(views_to_delete, uri, ctx, continue_on_error=ignore_errors)
    utils.exit_action(ctx, success=True, message="Successfully replaced view settings.")


def delete_views(
    views_to_delete: list[dict],
    uri: str,
    ctx: click.Context,
    continue_on_error: bool = False,
) -> None:
    """
    Delete views from a specified URI, handling errors according to the continue_on_error flag.
    Args:
        views_to_delete: List of dictionaries, each containing 'name' and 'view' keys.
        uri: Base URI for the delete requests.
        ctx: Click context for HTTP requests and logging.
        continue_on_error: If False, abort on the first error; otherwise, log warnings and continue.
    """
    for item in views_to_delete:
        name, view_item = item["name"], item["view"]
        delete_uri = f"{uri}/{name}/{view_item}"
        ctx.obj.logger.info(f"Deleting view '{view_item}' from '{name}'.")
        r = utils.http_delete(delete_uri, ctx)
        if r.status_code == 204:
            ctx.obj.logger.info(f"Successfully deleted view '{view_item}' from '{name}'.")
        else:
            error_message = f"Failed to delete view '{view_item}' from '{name}'."
            ctx.obj.logger.error(error_message)
            if not continue_on_error:
                utils.exit_action(ctx, success=False, message=error_message, response=r)


def add_views(
    views_to_add: list[dict],
    uri: str,
    ctx: click.Context,
    continue_on_error: bool = False,
) -> None:
    """
    Add views to a specified URI, handling errors according to the continue_on_error flag.
    Args:
        views_to_add: List of dictionaries, each containing 'name' and 'view' keys.
        uri: Base URI for the POST requests.
        ctx: Click context for HTTP requests and logging.
        continue_on_error: If True, log warnings and continue on error; otherwise, abort.
    """
    for item in views_to_add:
        name, view_item = item["name"], item["view"]
        add_uri = f"{uri}/{name}"
        ctx.obj.logger.info(f"Adding view '{view_item}' to '{name}'.")
        r = utils.http_post(add_uri, ctx, payload={"name": view_item})
        if r.status_code == 204:
            ctx.obj.logger.info(f"Successfully added view '{view_item}' to '{name}'.")
        else:
            error_message = f"Failed to add view '{view_item}' to '{name}'."
            ctx.obj.logger.error(error_message)
            if not continue_on_error:
                utils.exit_action(ctx, success=False, message=error_message, response=r)


def get_upstream_views(ctx: click.Context, uri: str) -> list[dict]:
    """
    Get and reformat upstream view settings.
    Args:
        ctx: Click context for HTTP requests and logging.
        uri: Base URI for upstream API requests.
    Returns:
        A list of upstream settings, each entry contains dictionaries with 'name' and 'views'.
    """
    ctx.obj.logger.debug(f"Fetching upstream views from {uri}.")
    upstream_views = utils.read_settings_from_upstream(uri, ctx)["views"]
    upstream_settings = []
    for key in upstream_views:
        zone_uri = f"{uri}/{key}"
        ctx.obj.logger.debug(f"Fetching zones for view '{key}' from {zone_uri}.")
        zones = utils.read_settings_from_upstream(zone_uri, ctx)["zones"]
        upstream_settings.append({"name": key, "views": set(zones)})
    ctx.obj.logger.info(f"Successfully fetched {len(upstream_settings)} upstream view settings.")
    return upstream_settings


def reformat_view_imports(ctx: click.Context, local_views: list[dict]) -> list[dict]:
    """
    Reformat local view settings for comparison with upstream settings.
    Args:
        local_views: List of local view configurations.
    Returns:
        A list with restructured local settings, each containing 'name' and 'views' as a set.
    """
    restructured_settings = []
    for item in local_views:
        view_name = next(iter(item.keys()))
        view_zones = next(iter(item.values()))
        canonical_zones = {make_canonical(view_item) for view_item in view_zones}
        restructured_settings.append({"name": view_name, "views": canonical_zones})
        ctx.obj.logger.debug(f"Reformatted view '{view_name}' with zones: {canonical_zones}.")
    ctx.obj.logger.info(f"Reformatted {len(restructured_settings)} local view settings.")
    return restructured_settings


def validate_view_import(ctx: click.Context, settings: list) -> bool:
    """
    Validate the structure of view import settings.
    Args:
        settings: A list of dictionaries, each with a single key-value pair.
                 The value should be a list of views.
    Returns:
        bool: True if all items are valid, False otherwise.
    """
    if not isinstance(settings, list):
        ctx.obj.logger.error("Settings must be a list of dictionaries.")
        return False
    for item in settings:
        if not isinstance(item, dict) or len(item) != 1:
            ctx.obj.logger.error("Each setting must be a dictionary with a single key-value pair.")
            return False
        value = next(iter(item.values()))
        if not isinstance(value, list):
            ctx.obj.logger.error("Each view's value must be a list of zones.")
            return False
    ctx.obj.logger.info("View import settings are valid.")
    return True


def is_zone_in_view(ctx: click.Context, new_view: dict, upstream: list[dict]) -> bool:
    """Check if all zones in a new view are present in an upstream view of the same name.
    Args:
        new_view: Dictionary with 'name' and 'views' (set or list of zones).
        upstream: List of dictionaries, each with 'name' and 'views' (set or list of zones).
    Returns:
        bool: True if an upstream view with the same name contains all zones, False otherwise.
    """
    for upstream_view in upstream:
        if upstream_view["name"] == new_view["name"]:
            if all(item in upstream_view["views"] for item in new_view["views"]):
                ctx.obj.logger.info(f"All zones in view '{new_view['name']}' are present upstream.")
                return True
            missing_zones = set(new_view["views"]) - set(upstream_view["views"])
            ctx.obj.logger.info(
                f"View '{new_view['name']}' is missing zones upstream: {missing_zones}."
            )
            return False
    ctx.obj.logger.info(f"No upstream view named '{new_view['name']}' found.")
    return False


def make_canonical(zone: str) -> str:
    """Ensure a DNS zone name ends with a trailing dot.
    Args:
        zone: The DNS zone name (e.g., "example.com").
    Returns:
        The zone name with a trailing dot if not already present.
    """
    return zone if zone.endswith(".") else zone + "."
