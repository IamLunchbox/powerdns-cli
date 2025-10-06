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

import click

from ..utils import main as utils
from ..utils.validation import PowerDNSZone


@click.group()
@click.pass_context
def view(ctx):
    """Set view to limit zone access"""
    if ctx.obj.config["major_version"] < 5:
        utils.print_output({"error": "Your authoritative dns-server does not support views"})
        raise SystemExit(1)


@view.command("add")
@click.argument("view_id", type=click.STRING, metavar="view")
@click.argument("dns_zone", type=PowerDNSZone, metavar="zone")
@click.pass_context
def view_add(ctx, view_id, dns_zone):
    """Add a zone to a view, creates the view if it did not exist beforehand"""
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/views/{view_id}"
    view_content = utils.http_get(uri, ctx)
    if view_content.status_code == 200 and dns_zone in view_content.json()["zones"]:
        utils.print_output({"message": f"{dns_zone} already in {view_id}"})
        raise SystemExit(0)
    payload = {"name": f"{dns_zone}"}
    r = utils.http_post(uri, ctx, payload=payload)
    if utils.create_output(r, (204,), optional_json={"message": f"Added {dns_zone} to {view_id}"}):
        raise SystemExit(0)
    raise SystemExit(1)


@view.command("delete")
@click.argument("view_id", type=click.STRING, metavar="view")
@click.argument("dns_zone", type=PowerDNSZone, metavar="zone")
@click.pass_context
def view_delete(ctx, view_id, dns_zone):
    """Deletes a dns-zone from a view"""
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/views/{view_id}"
    view_content = utils.http_get(uri, ctx)
    if view_content.status_code == 200 and dns_zone not in view_content.json()["zones"]:
        utils.print_output({"message": f"Zone {dns_zone} is not in {view_id}"})
        raise SystemExit(0)
    if view_content.status_code == 404:
        utils.print_output({"message": f"View {view_id} is absent"})
        raise SystemExit(0)
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/views/{view_id}/{dns_zone}"
    r = utils.http_delete(uri, ctx)
    if utils.create_output(
        r, (204,), optional_json={"message": f"Deleted {dns_zone} from {view_id}"}
    ):
        raise SystemExit(0)
    raise SystemExit(1)


@view.command("export")
@click.argument("view_id", type=click.STRING, metavar="view")
@click.pass_context
def view_export(ctx, view_id):
    """
    Exports a single view for its configured zones
    """
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/views/{view_id}"
    r = utils.http_get(uri, ctx)
    if utils.create_output(r, (200,)):
        raise SystemExit(0)
    raise SystemExit(1)


@view.command("import")
@click.argument("file", type=click.File())
@click.option(
    "--replace",
    type=click.BOOL,
    is_flag=True,
    help="Replace all view settings with new ones",
)
@click.option("--ignore-errors", is_flag=True, help="Continue import even when requests fail")
@click.pass_context
def view_import(ctx, file, replace, ignore_errors):
    """Imports views and their contents into the server.
    Must be a list dictionaries, like so: [{'view1':['example.org']}]
    """
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/views"
    settings = utils.extract_file(file)
    if not validate_view_import(settings):
        utils.print_output(
            {
                "error": "Views must be provided in the following structure:"
                "[{'view1':['example.org']}]"
            },
        )
        raise SystemExit(1)
    restructured_settings = reformat_view_imports(settings)
    upstream_settings = get_upstream_views(uri, ctx)
    if replace and upstream_settings == restructured_settings:
        utils.print_output({"message": "Requested views are already present"})
        raise SystemExit(0)
    if not replace and all(
        is_zone_in_view(view_item, upstream_settings) for view_item in restructured_settings
    ):
        utils.print_output({"message": "Requested views are already present"})
        raise SystemExit(0)

    if replace and upstream_settings:
        replace_view_import(uri, ctx, restructured_settings, upstream_settings, ignore_errors)
    else:
        add_view_import(uri, ctx, restructured_settings, ignore_errors)
    utils.print_output(
        {"message": "Successfully imported zones"},
    )
    raise SystemExit(0)


@view.command("list")
@click.pass_context
def view_list(ctx):
    """
    Shows all views and their configuration as a list
    """
    uri = f"{ctx.obj.config['apihost']}/api/v1/servers/localhost/views"
    r = utils.http_get(uri, ctx)
    if utils.create_output(r, (200,)):
        raise SystemExit(0)
    raise SystemExit(1)


@view.command("spec")
def view_spec():
    """Open the view specification on https://redocly.github.io"""

    utils.open_spec("view")


# pylint: disable=unused-argument
@view.command("update")
@click.argument("view_id", type=click.STRING, metavar="view")
@click.argument("dns_zone", type=PowerDNSZone, metavar="zone")
@click.pass_context
def view_update(ctx, view_id, dns_zone):
    """Update a view to contain the given zone"""
    ctx.forward(view_add)


# pylint: enable=unused-argument


def add_view_import(uri: str, ctx: click.Context, settings: list, ignore_errors: bool) -> None:
    """
    Import views from settings configuration.

    Args:
        uri: The connection string
        ctx: Click context object for CLI operations
        settings: List of view configuration dictionaries, each containing
                 'name' and 'views' keys
        ignore_errors: Whether to continue processing if errors occur

    Raises:
        SystemExit: If subsequent requests encounter an error and ignore_errors is True
    """
    views_to_add = [
        {"name": view_entry["name"], "view": view_item}
        for view_entry in settings
        for view_item in view_entry["views"]
    ]

    if views_to_add:
        add_views(views_to_add, uri, ctx, continue_on_error=ignore_errors)


def replace_view_import(
    uri: str, ctx: click.Context, settings: list, upstream_settings: list, ignore_errors: bool
) -> None:
    """
    Replace views by comparing current settings with upstream settings.

    This function performs a differential update:
    - Deletes views that exist in upstream but not in current settings
    - Adds new views that exist in current but not in upstream settings
    - For matching view names, adds/removes individual views based on set difference

    Args:
        uri: Database URI or connection string
        ctx: Click context object for CLI operations
        settings: Current view configuration (target state)
        upstream_settings: Previous view configuration (current state)
        ignore_errors: Whether to continue processing if errors occur
    """
    views_to_add = []
    views_to_delete = []
    for old_view in upstream_settings:
        # if a view name is not in the name set, delete it and its contents completely
        if old_view["name"] not in [viewset["name"] for viewset in settings]:
            for item in old_view["views"]:
                views_to_delete.append({"name": old_view["name"], "view": item})
            continue
        # the new view name is present, intersect the content
        for new_view in settings:
            if old_view["name"] == new_view["name"]:
                for item in new_view["views"].difference(old_view["views"]):
                    views_to_add.append({"name": old_view["name"], "view": item})
                for item in old_view["views"].difference(new_view["views"]):
                    views_to_delete.append({"name": old_view["name"], "view": item})
            if new_view["name"] not in [viewset["name"] for viewset in upstream_settings]:
                for item in new_view["views"]:
                    views_to_add.append({"name": new_view["name"], "view": item})

    add_views(views_to_add, uri, ctx, continue_on_error=ignore_errors)
    delete_views(views_to_delete, uri, ctx, continue_on_error=ignore_errors)


def delete_views(
    views_to_delete: list[dict],
    uri: str,
    ctx: click.Context,
    continue_on_error: bool = False,
) -> None:
    """Delete views from a specified URI, handling errors according to the abort_on_error flag.

    Args:
        views_to_delete: List of dictionaries, each containing 'name' and 'view' keys.
        uri: Base URI for the delete requests.
        ctx: Click context for HTTP requests.
        continue_on_error: If False, abort on the first error; otherwise, log warnings and continue.

    Raises:
        SystemExit: If continue_on_error is True and a request fails.
    """
    for item in views_to_delete:
        name, view_item = item["name"], item["view"]
        r = utils.http_delete(f"{uri}/{name}/{view_item}", ctx)

        if r.status_code != 204:
            utils.handle_import_early_exit(
                ctx,
                f"Failed to delete view '{view_item}' from '{name}",
                continue_on_error,
            )


def add_views(
    views_to_add: list[dict],
    uri: str,
    ctx: click.Context,
    continue_on_error: bool = False,
) -> None:
    """Add views to a specified URI, handling errors according to the continue_on_error flag.

    Args:
        views_to_add: List of dictionaries, each containing 'name' and 'view' keys.
        uri: Base URI for the POST requests.
        ctx: Click context for HTTP requests.
        continue_on_error: If True, log warnings and continue on error; otherwise, abort.

    Raises:
        SystemExit: If continue_on_error is False and a request fails.
    """
    for item in views_to_add:
        name, view_item = item["name"], item["view"]
        r = utils.http_post(f"{uri}/{name}", ctx, payload={"name": view_item})

        if r.status_code != 204:
            utils.handle_import_early_exit(
                ctx,
                f"Failed to add view '{view_item}' to '{name}'",
                continue_on_error,
            )


def get_upstream_views(uri: str, ctx) -> list[dict]:
    """Get and reformat upstream view settings.

    Args:
        uri: Base URI for upstream API requests.
        ctx: Click context for HTTP requests.

    Returns:
        A list of upstream settings, each entry contains dictionaries with 'name' and 'views'.
    """
    upstream_views = utils.read_settings_from_upstream(uri, ctx)["views"]
    upstream_settings = [
        {
            "name": key,
            "views": set(utils.read_settings_from_upstream(f"{uri}/{key}", ctx)["zones"]),
        }
        for key in upstream_views
    ]
    return upstream_settings


def reformat_view_imports(local_views: list) -> list[dict]:
    """Reformat local and upstream view settings for comparison.

    Args:
        local_views: List of local view configurations.

    Returns:
        A list with restructured local settings, it contains dictionaries with 'name' and 'views'.
    """
    restructured_settings = [
        {
            "name": next(iter(item.keys())),
            "views": {utils.make_canonical(view_item) for view_item in next(iter(item.values()))},
        }
        for item in local_views
    ]
    return restructured_settings


def validate_view_import(settings: list) -> bool:
    """Validate the structure of view import settings.

    Args:
        settings: A list of dictionaries, each with a single key-value pair.
                 The value should be a list of views.

    Returns:
        bool: True if all items are valid, False otherwise.
    """
    if not isinstance(settings, list):
        return False

    for item in settings:
        if not isinstance(item, dict) or len(item) != 1:
            return False
        value = next(iter(item.values()))
        if not isinstance(value, list):
            return False

    return True


def is_zone_in_view(new_view: dict, upstream: list[dict]) -> bool:
    """Check if all zones in a new view are present in an upstream view of the same name.

    Args:
        new_view: Dictionary with 'name' and 'views' (set or list of zones).
        upstream: List of dictionaries, each with 'name' and 'views' (set or list of zones).

    Returns:
        bool: True if an upstream view with the same name contains all zones, False otherwise.
    """
    return any(
        upstream_view["name"] == new_view["name"]
        and all(item in upstream_view["views"] for item in new_view["views"])
        for upstream_view in upstream
    )
