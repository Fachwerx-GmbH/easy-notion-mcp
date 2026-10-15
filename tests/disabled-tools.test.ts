import { describe, it, expect } from "vitest";
import { Client } from "@modelcontextprotocol/client";
import { InMemoryTransport } from "@modelcontextprotocol/server";
import { createServer } from "../src/server.js";

describe("disabledTools", () => {
  it("hides a disabled tool from tools/list and refuses to call it", async () => {
    const server = createServer(() => ({}) as never, { transport: "http", disabledTools: ["delete_view"] });
    const client = new Client({ name: "t", version: "1" });
    const [a, b] = InMemoryTransport.createLinkedPair();
    await Promise.all([server.connect(a), client.connect(b)]);

    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name)).not.toContain("delete_view");
    expect(tools.map((t) => t.name)).toContain("delete_database_entry");

    const result = await client.callTool({ name: "delete_view", arguments: { view_id: "x" } });
    expect(JSON.stringify(result.content)).toContain("disabled on this server");
  });
});
