export const state = {
  servers: [],
  agents: [],
  queries: [],
  auditPage: 1,
  auditData: null,
  querySort: { key: "name", direction: 1 },
  filters: { servers: {}, agents: {}, queries: {}, audit: {} },
  modal: { kind: "", item: null, initialValues: [] },
  deletion: { kind: "", id: null },
};
