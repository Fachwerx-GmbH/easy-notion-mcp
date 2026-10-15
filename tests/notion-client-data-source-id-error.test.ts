import { describe, expect, it, vi } from "vitest";
import { getCachedSchema, queryDatabase } from "../src/notion-client.js";

type MockClient = {
  dataSources: {
    retrieve: ReturnType<typeof vi.fn>;
  };
  databases: {
    retrieve: ReturnType<typeof vi.fn>;
  };
};

function objectNotFoundError(message = "Could not find database") {
  const error: any = new Error(message);
  error.code = "object_not_found";
  error.body = { code: "object_not_found", message };
  return error;
}

describe("data source IDs", () => {
  it("getCachedSchema resolves normally for a database container ID", async () => {
    const schema = { id: "ds-happy", properties: { Name: { type: "title" } } };
    const client: MockClient = {
      databases: {
        retrieve: vi.fn().mockResolvedValue({ id: "db-happy", data_sources: [{ id: "ds-happy" }] }),
      },
      dataSources: {
        retrieve: vi.fn().mockResolvedValue(schema),
      },
    };

    await expect(getCachedSchema(client as any, "db-happy")).resolves.toBe(schema);

    expect(client.databases.retrieve).toHaveBeenCalledWith({ database_id: "db-happy" });
    expect(client.dataSources.retrieve).toHaveBeenCalledWith({ data_source_id: "ds-happy" });
    expect(client.dataSources.retrieve).not.toHaveBeenCalledWith({ data_source_id: "db-happy" });
  });

  it("getCachedSchema accepts a data_source ID, the ID search returns for databases", async () => {
    const dataSource = {
      object: "data_source",
      id: "ds-direct",
      parent: { type: "database_id", database_id: "db-parent" },
      properties: { Name: { type: "title" } },
    };
    const client: MockClient = {
      databases: { retrieve: vi.fn().mockRejectedValue(objectNotFoundError()) },
      dataSources: { retrieve: vi.fn().mockResolvedValue(dataSource) },
    };

    await expect(getCachedSchema(client as any, "ds-direct")).resolves.toBe(dataSource);
    await expect(getCachedSchema(client as any, "ds-direct")).resolves.toBe(dataSource);
    expect(client.databases.retrieve).toHaveBeenCalledTimes(1);
  });

  it("queryDatabase queries a data_source ID directly", async () => {
    const client = {
      databases: { retrieve: vi.fn().mockRejectedValue(objectNotFoundError()) },
      dataSources: {
        retrieve: vi.fn().mockResolvedValue({ object: "data_source", id: "ds-query", properties: {} }),
        query: vi.fn().mockResolvedValue({ results: [{ id: "row-1" }], has_more: false, next_cursor: null }),
      },
    };

    await expect(queryDatabase(client as any, "ds-query")).resolves.toEqual([{ id: "row-1" }]);
    expect(client.dataSources.query).toHaveBeenCalledWith(expect.objectContaining({ data_source_id: "ds-query" }));
  });

  it("getCachedSchema preserves original object_not_found when neither database nor data source exists", async () => {
    const original: any = new Error("Could not find database");
    original.code = "object_not_found";
    original.body = { code: "object_not_found", message: "Could not find database" };
    const fallback = objectNotFoundError("Could not find data source");
    const client: MockClient = {
      databases: {
        retrieve: vi.fn().mockRejectedValue(original),
      },
      dataSources: {
        retrieve: vi.fn().mockRejectedValue(fallback),
      },
    };

    await expect(getCachedSchema(client as any, "db-missing-specific")).rejects.toBe(original);
    expect(client.dataSources.retrieve).toHaveBeenCalledWith({ data_source_id: "db-missing-specific" });
  });
});
