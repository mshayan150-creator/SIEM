/* Run from repository root: SIEM_TEST_PYTHON=.venv/bin/python node tests/ui_smoke.cjs
 * Install playwright in your dev environment first; no production JS dependencies.
 * SIEM_SCREENSHOTS optionally names an existing private directory for visual QA.
 */
const { chromium } = require("playwright");
const { spawn } = require("node:child_process");
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const path = require("node:path");
const base = "http://127.0.0.1:8765";
const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

(async () => {
  const server = spawn(
    process.env.SIEM_TEST_PYTHON || "python",
    [
      "-m",
      "uvicorn",
      "tests.ui_fixture:app",
      "--host",
      "127.0.0.1",
      "--port",
      "8765",
      "--no-access-log",
    ],
    { stdio: ["ignore", "pipe", "pipe"] },
  );
  let serverOutput = "";
  server.stdout.on("data", (chunk) => {
    serverOutput += chunk;
  });
  server.stderr.on("data", (chunk) => {
    serverOutput += chunk;
  });
  let browser;
  try {
    let ready = false;
    for (let i = 0; i < 80; i++) {
      if (server.exitCode !== null) throw new Error(serverOutput);
      try {
        ready = (await fetch(base + "/health/live")).ok;
      } catch {
        /* starting */
      }
      if (ready) break;
      await wait(100);
    }
    assert(ready, serverOutput || "Fixture server did not start");
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage({
      viewport: { width: 1440, height: 1000 },
    });
    const errors = [];
    page.on("pageerror", (error) => errors.push(error.message));
    async function screenshot(name) {
      if (process.env.SIEM_SCREENSHOTS)
        await page.screenshot({
          path: path.join(process.env.SIEM_SCREENSHOTS, name + ".png"),
          fullPage: true,
        });
    }
    async function refresh() {
      const response = page.waitForResponse((r) =>
        r.url().includes("/snapshot?"),
      );
      await page.locator("#refresh").click();
      await response;
      await page.locator("#refresh:not([disabled])").waitFor();
    }
    async function login(username, password) {
      await page.locator("#username").fill(username);
      await page.locator("#key").fill(password);
      await page.locator("#login-form button").click();
      await page.locator("#console").waitFor({ state: "visible" });
    }
    await page.goto(base);
    // HTML patterns use Unicode Sets (v), whose character classes require escaped hyphens.
    await page.evaluate(() => {
      for (const input of document.querySelectorAll("input[pattern]")) {
        new RegExp(input.pattern, "v");
      }
    });
    await page.locator("#username").fill("Invalid User");
    assert.equal(await page.locator("#username").evaluate((el) => el.checkValidity()), false);
    await page.locator("#username").fill("valid-user.name_1");
    assert.equal(await page.locator("#username").evaluate((el) => el.checkValidity()), true);
    await screenshot("login");
    await login("admin", "Browser Test Password 2026!");
    assert.equal(await page.locator("#event-count").textContent(), "3");
    await screenshot("overview-desktop");
    await page.locator("#pause").click();
    assert.equal(
      await page.locator("#pause").getAttribute("aria-pressed"),
      "true",
    );
    await page.locator("#view-failures").click();
    assert.equal(await page.locator("#event-list tr").count(), 1);
    assert.equal(await page.locator("#outcome").inputValue(), "failure");
    assert.equal(await page.locator("#event-list img").count(), 0);
    assert((await page.locator("#event-list").textContent()).includes("<img"));
    await page.locator("#event-list button").first().click();
    await page.locator("#detail-dialog").waitFor({ state: "visible" });
    const detailBefore = await page.locator("#detail-json").textContent();
    await page.keyboard.press("Escape");
    await refresh();
    await page.locator("#event-list button").first().focus();
    await refresh();
    // Refresh button intentionally gains focus during manual refresh; focused result keys
    // are preserved during periodic refreshes, covered below with a live dialog.
    await page.locator("#event-list button").first().click();
    await page.keyboard.press("Escape");
    await page.locator("#pause").click();
    await page.locator("#event-list button").first().click();
    await page.waitForResponse((r) => r.url().includes("/snapshot?"), {
      timeout: 8000,
    });
    assert(await page.locator("#detail-dialog").isVisible());
    assert.equal(
      await page.locator("#detail-json").textContent(),
      detailBefore,
    );
    await page.keyboard.press("Escape");
    await page.locator("#pause").click();
    const exportWait = page.waitForEvent("download");
    await page.locator("#export-events").click();
    const exported = await exportWait;
    const exportedJson = JSON.parse(
      await fs.readFile(await exported.path(), "utf8"),
    );
    assert.equal(exportedJson.events.length, 1);
    assert.equal(exportedJson.outcome, "failure");
    await page.locator("#outcome").selectOption("all");
    await page.locator("#event-sort").selectOption("oldest");
    assert.equal(await page.locator("#event-list tr").count(), 3);
    await screenshot("events-desktop");
    await page.locator("#search").fill("no-such-record");
    const searched = page.waitForResponse((r) =>
      r.url().includes("/snapshot?q=no-such-record"),
    );
    await page
      .locator(
        '#search-form button[type="submit"], #search-form button.primary',
      )
      .click();
    await searched;
    await page.getByText("No events to show", { exact: true }).waitFor();
    const cleared = page.waitForResponse((r) =>
      r.url().endsWith("/snapshot?q="),
    );
    await page.locator("#clear-search").click();
    await cleared;
    await page.locator("#event-list button").first().waitFor();
    await page.locator('[data-view="alerts"]').click();
    await page.locator("#severity").selectOption("high");
    assert(
      await page
        .getByText("No matching incidents", { exact: true })
        .isVisible(),
    );
    await page.locator("#severity").selectOption("all");
    await page.locator("#alert-list button").first().click();
    assert(
      (await page.locator("#detail-json").textContent()).includes("evidence"),
    );
    await screenshot("incident-detail");
    await page.keyboard.press("Escape");
    await page.locator('[data-view="settings"]').click();
    await page.locator("#users .row").first().waitFor();
    assert(await page.locator("#users button").first().isDisabled());
    await page.getByText("Create an account", { exact: true }).click();
    await page.locator("#new-user").fill("viewer");
    await page.locator("#new-password").fill("Viewer Test Password 2026!");
    await page.locator("#create-user button").click();
    await page.locator("#users .row").filter({ hasText: "viewer" }).waitFor();
    await page.locator("#new-host").fill("REMOTE-PC");
    const enrolledWait = page.waitForEvent("download");
    await page.locator("#create-collector button").click();
    assert.equal(
      (await enrolledWait).suggestedFilename(),
      "collector-REMOTE-PC.json",
    );
    const registered = page
      .locator("#registered-collectors .row")
      .filter({ hasText: "REMOTE-PC" });
    await registered.waitFor();
    await registered.getByRole("button", { name: "Revoke" }).click();
    await page.locator("#confirm-cancel").click();
    assert(
      await registered.getByRole("button", { name: "Revoke" }).isVisible(),
    );
    await registered.getByRole("button", { name: "Revoke" }).click();
    await page.locator("#confirm-accept").click();
    await page
      .locator("#registered-collectors .row")
      .filter({ hasText: "Revoked" })
      .waitFor();
    await screenshot("settings-desktop");
    await page.request.post(base + "/qa/failure/true");
    await refresh();
    assert.equal(await page.locator("#live-state").textContent(), "Data stale");
    assert(
      (await page.locator("#notice").textContent()).includes("out of date"),
    );
    await page.request.post(base + "/qa/failure/false");
    await refresh();
    assert(await page.locator("#notice").isHidden());
    await page.locator('[data-view="overview"]').click();
    await page.setViewportSize({ width: 390, height: 844 });
    await screenshot("overview-mobile");
    assert(await page.evaluate(() => document.body.scrollWidth <= innerWidth));
    await page.keyboard.press("/");
    assert(
      await page
        .locator("#search")
        .evaluate((node) => node === document.activeElement),
    );
    await screenshot("events-mobile");
    assert(await page.evaluate(() => document.body.scrollWidth <= innerWidth));
    await page.locator("#logout").click();
    await login("viewer", "Viewer Test Password 2026!");
    await page.locator('[data-view="settings"]').click();
    assert(await page.locator("#admin").isHidden());
    assert.equal(
      (await page.request.get(base + "/api/v1/dashboard/admin")).status(),
      403,
    );
    await page.getByText("Change password", { exact: true }).click();
    await page.locator("#current-password").fill("Viewer Test Password 2026!");
    await page
      .locator("#changed-password")
      .fill("Replaced Viewer Password 2026!");
    await page.locator("#change-password button").click();
    await page.locator("#login").waitFor({ state: "visible" });
    assert.deepEqual(errors, []);
    console.log(
      "PASS: navigation, filters/search/export, retained detail on live refresh, escaped logs, admin enrollment/revoke confirmation, stale recovery, responsive layout, keyboard search, viewer permissions, password change.",
    );
  } finally {
    await browser?.close();
    server.kill("SIGTERM");
    await new Promise((resolve) => {
      if (server.exitCode !== null) resolve();
      else server.once("exit", resolve);
    });
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
