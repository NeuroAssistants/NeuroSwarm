"""Live console ordering, tenancy and access through the normal HTTP routes."""
try:
    from .test_security import ServerHarness
except ImportError:
    from test_security import ServerHarness


class LiveConsoleTests(ServerHarness):
    def test_ordered_combined_records_are_organization_scoped(self):
        url = "/api/v1/live-records"
        self.assertEqual(self.req("GET", url)[0], 401)
        self.assertEqual(self.login()[0], 200)
        self.ctx.db.execute("""INSERT INTO events(host_id,harness,agent_name,event_type,severity,message,created_at)
            VALUES('station','observer','worker','notice','INFO','Job finished',1)""")
        self.ctx.db.execute("""INSERT INTO alerts(host_id,rule_code,severity,title,summary,created_at,updated_at)
            VALUES('station','CPU','WARNING','CPU high','Observed above threshold',1,2)""")
        status, body, _ = self.req("GET", url)
        self.assertEqual(status, 200)
        self.assertEqual([(r["kind"], r["message"]) for r in body["records"]],
                         [("Alert", "CPU high"), ("Event", "Job finished")])
        self.assertEqual(self.req("GET", url, headers=self.bearer(self.token()), cookie=False)[0], 401)
        status, _, headers = self.req("POST", "/api/v1/auth/register",
                                      {"username":"second-user","organization":"Second org","password":"LiveConsoleSample!2026"}, cookie=False)
        self.assertEqual(status, 201)
        self.cookie = headers["set-cookie"].split(";")[0]
        status, other, _ = self.req("GET", url)
        self.assertEqual(status, 200)
        self.assertNotEqual(other["organization"], body["organization"])
        self.assertEqual(other["records"], [])
