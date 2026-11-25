"""Exercise the installed panel using a real browser; the installer log is private."""
import re
import sys
from pathlib import Path

from playwright.sync_api import expect, sync_playwright

password = re.search(r"^ttui /ttui \| admin \| (\S+)$", Path(sys.argv[1]).read_text(), re.M)[1]
base = "http://127.0.0.1:8080/ttui"

with sync_playwright() as playwright:
    browser = playwright.chromium.launch()
    page = browser.new_page(viewport={"width": 390, "height": 844}, is_mobile=True, has_touch=True)
    page.goto(base + "/login")
    page.get_by_label("Username").fill("admin")
    page.get_by_label("Password", exact=True).fill(password)
    page.get_by_role("button", name="Sign in").click()
    expect(page.get_by_role("heading", name="Dashboard")).to_be_visible()
    page.get_by_role("link", name="Clients", exact=True).click()
    page.get_by_label("Username", exact=True).fill("browser-test")
    page.get_by_role("button", name="Add", exact=True).click()
    expect(page.get_by_text("Clients updated.")).to_be_visible()
    page.get_by_text("browser-test", exact=True).first.click()
    page.get_by_role("button", name="Export", exact=True).first.click()
    expect(page.locator("#export-value")).to_have_value(re.compile(r"^tt://\?"))
    page.goto(base + "/routing")
    page.get_by_role("button", name="Add outbound").click()
    page.get_by_label("Outbound name").fill("browser-proxy")
    page.get_by_label("Proxy address").fill("127.0.0.1")
    page.get_by_label("Port", exact=True).fill("1080")
    page.get_by_role("button", name="Add rule").click()
    page.get_by_label("Outbound", exact=True).last.select_option("browser-proxy")
    page.get_by_label("Domains, one per line").last.fill(r"regexp:^browser\.example$")
    page.get_by_role("button", name="Apply routing").click()
    expect(page.get_by_text("Routing settings saved.")).to_be_visible()
    expect(page.get_by_label("Outbound name")).to_have_value("browser-proxy")
    expect(page.get_by_label("Domains, one per line").last).to_have_value(r"regexp:^browser\.example$")
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), "Mobile page overflows horizontally"
    browser.close()
