def response(flow):
    flow.response.headers["X-Mitmdump"] = "1"
