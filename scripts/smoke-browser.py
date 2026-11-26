"""Exercise the installed panel using a real browser; the installer log is private."""
import re
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from playwright.sync_api import expect, sync_playwright

password = re.search(r"^ttui /ttui \| admin \| (\S+)$", Path(sys.argv[2]).read_text(), re.M)[1]
base = "http://127.0.0.1:8080/ttui"

with sync_playwright() as playwright:
    browser = playwright.chromium.launch()
    page = browser.new_page(viewport={"width": 390, "height": 844}, is_mobile=True, has_touch=True)
    page.goto(base + "/login")
    page.get_by_label("Username").fill("admin")
    page.get_by_label("Password", exact=True).fill(password)
    page.get_by_role("button", name="Sign in").click()
    expect(page.get_by_role("heading", name="Dashboard")).to_be_visible()
    expect(page.get_by_text("Services", exact=True)).to_be_visible()
    expect(page.get_by_text("Administrator sign-in", exact=True).first).to_be_visible()
    page.get_by_role("link", name="Clients", exact=True).click()
    for name in ("browser-test", "browser-one", "browser-two"):
        page.get_by_role("button", name="Add client").click()
        dialog = page.locator("#add-client")
        dialog.get_by_label("Username", exact=True).fill(name)
        dialog.get_by_role("button", name="Add client").click()
        expect(page.get_by_text("Clients updated.")).to_be_visible()

    def select_clients():
        for name in ("browser-one", "browser-two"):
            page.get_by_label("Select " + name).check()

    select_clients()
    page.get_by_role("button", name="Disable selected").click()
    expect(page.get_by_text("Clients updated.")).to_be_visible()
    for name in ("browser-one", "browser-two"):
        expect(page.locator("tr[data-client-row]").filter(has_text=name)).to_contain_text("Disabled")
    select_clients()
    page.get_by_role("button", name="Enable selected").click()
    expect(page.get_by_text("Clients updated.")).to_be_visible()
    for name in ("browser-one", "browser-two"):
        expect(page.locator("tr[data-client-row]").filter(has_text=name)).to_contain_text("Enabled")
    select_clients()
    page.once("dialog", lambda dialog: dialog.accept())
    page.get_by_role("button", name="Delete selected").click()
    expect(page.get_by_text("Clients updated.")).to_be_visible()
    expect(page.get_by_text("browser-one", exact=True)).to_have_count(0)
    page.get_by_role("button", name="Export", exact=True).first.click()
    expect(page.locator("#export-value")).to_have_value(re.compile(r"^tt://\?"))
    page.goto(base + "/endpoint")
    page.get_by_role("tab", name="Network").click()
    page.get_by_label("TCP idle", exact=True).fill("604799")
    page.get_by_role("button", name="Preview changes").click()
    expect(page.get_by_label("Configuration diff")).to_have_value(re.compile("604799"))
    page.get_by_role("button", name="Apply and restart").click()
    expect(page.get_by_text("TrustTunnel settings applied.")).to_be_visible()
    page.goto(base + "/tls")
    with TemporaryDirectory() as directory:
        cert, key = Path(directory) / "cert.pem", Path(directory) / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                        "-subj", "/CN=browser.example", "-addext", "subjectAltName=DNS:browser.example",
                        "-out", str(cert), "-keyout", str(key)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        add_host = page.locator("section").filter(has=page.get_by_role("heading", name="Add TLS host"))
        add_host.get_by_label("Hostname").fill("browser.example")
        add_host.get_by_label("Purpose").select_option("ping_hosts")
        add_host.get_by_text("Upload certificate and private key").click()
        add_host.get_by_label("Certificate chain (PEM)").set_input_files(str(cert))
        add_host.get_by_label("Private key (PEM)").set_input_files(str(key))
        add_host.get_by_role("button", name="Add host").click()
    expect(page.get_by_text("TLS hosts updated.")).to_be_visible()
    expect(page.get_by_text("browser.example", exact=False).first).to_be_visible()
    add_host = page.locator("section").filter(has=page.get_by_role("heading", name="Add TLS host"))
    add_host.get_by_label("Hostname").fill("smoke.example")
    add_host.get_by_label("Purpose").select_option("ping_hosts")
    add_host.get_by_role("button", name="Add host").click()
    expect(page.get_by_text("This hostname already exists in another TLS host entry.")).to_be_visible()
    page.goto(base + "/routing")
    page.get_by_role("button", name="Add outbound").click()
    page.get_by_label("Outbound name").last.fill("browser-proxy")
    page.get_by_label("Proxy address").fill("127.0.0.1")
    page.get_by_label("Port", exact=True).fill("1080")
    page.get_by_role("button", name="Add rule").click()
    page.get_by_label("Outbound", exact=True).last.select_option("browser-proxy")
    page.get_by_label("Domains, one per line").last.fill(r"regexp:^browser\.example$")
    page.get_by_role("button", name="Apply routing").click()
    expect(page.get_by_text("Routing settings saved.")).to_be_visible()
    expect(page.get_by_label("Outbound name").last).to_have_value("browser-proxy")
    expect(page.get_by_label("Domains, one per line").last).to_have_value(r"regexp:^browser\.example$")
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), "Mobile page overflows horizontally"
    browser.close()
