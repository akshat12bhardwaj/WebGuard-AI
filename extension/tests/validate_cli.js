// Validate a saved API response with the extension's own parser: node validate_cli.js response.json
import { readFileSync } from "node:fs";
import { validateResponse, viewModel } from "../api.js";

const body = JSON.parse(readFileSync(process.argv[2], "utf8"));
const problems = validateResponse(body);
if (problems.length) {
  console.error(problems.join("; "));
  process.exit(1);
}
const v = viewModel(body);
console.log(JSON.stringify({ category: v.category, ti: v.threatIntel.map((t) => t.status), rules: v.rules.length }));
