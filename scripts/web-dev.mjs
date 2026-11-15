// OP-69, OP-159 m.40: rebuilds the web apps on save and restarts the local access-server, which
// reads each dist directory once at start, so the change shows on the next page load.
import { spawn, spawnSync } from "node:child_process";
import { existsSync, readFileSync, watch } from "node:fs";
import { join } from "node:path";

const root = join(import.meta.dirname, "..");
const apps = ["login", "account", "console"];
const compose = ["compose", "-f", "deploy/compose/access.yaml", "-f", "deploy/compose/access-web.yaml"];
const password = join(root, "target", "local-test-password");
const env = {
  ...process.env,
  ACCESS_IMAGE: process.env.ACCESS_IMAGE ?? "access-local:build",
  ACCESS_LOCAL_TEST_PASSWORD:
    process.env.ACCESS_LOCAL_TEST_PASSWORD ??
    (existsSync(password) ? readFileSync(password, "utf8").trim() : ""),
};

function run(command, args) {
  const r = spawnSync(command, args, { cwd: root, env, stdio: "inherit" });
  if (r.status !== 0) process.exit(r.status ?? 1);
}

if (env.ACCESS_LOCAL_TEST_PASSWORD === "") {
  console.error("no target/local-test-password: run just start first");
  process.exit(1);
}

run("pnpm", ["--dir", "web", "exec", "turbo", "run", "build", "--filter=./apps/*"]);
run("docker", [...compose, "up", "-d", "--no-deps", "--wait", "access-server"]);

const children = apps.map((app) =>
  spawn("pnpm", ["exec", "vite", "build", "--watch", "--logLevel", "warn"], {
    cwd: join(root, "web", "apps", app),
    env,
    stdio: "inherit",
  }),
);

let timer;
let restarting = false;
let again = false;

function restart() {
  if (restarting) {
    again = true;
    return;
  }
  restarting = true;
  const started = Date.now();
  const child = spawn("docker", [...compose, "restart", "access-server"], { cwd: root, env, stdio: "ignore" });
  child.on("exit", (code) => {
    restarting = false;
    console.log(code === 0 ? `web-dev: served (${String(Date.now() - started)} ms)` : "web-dev: restart failed");
    if (again) {
      again = false;
      restart();
    }
  });
}

for (const app of apps) {
  watch(join(root, "web", "apps", app, "dist"), { recursive: true }, () => {
    clearTimeout(timer);
    timer = setTimeout(restart, 800);
  });
}

console.log("web-dev: watching login, account and console; Ctrl-C stops (just start serves the image's copies again)");

process.on("SIGINT", () => {
  for (const child of children) child.kill("SIGINT");
  process.exit(0);
});
