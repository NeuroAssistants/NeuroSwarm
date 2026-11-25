"""HTTP filtering/export and bookmarked diagnostic views against an isolated console."""
import json
import sqlite3
import time
import unittest
from urllib.parse import urlencode, urlsplit, parse_qs
import test_browser_live_readability as fixtures


class DiagnosticFiltersTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.LiveReadabilityBrowserTests.setUpClass.__func__(cls)
        cls.bounds = (int(time.time()) - 3600, int(time.time()) + 3600)
        with sqlite3.connect(cls.srv.db_path) as con:
            eid = cls.ids['curl_401']
            meta = json.loads(con.execute('SELECT metadata_json FROM events WHERE id=?', (eid,)).fetchone()[0])
            meta['web_resource'] = {'method': 'POST', 'status_code': 401}
            con.execute('UPDATE events SET metadata_json=? WHERE id=?', (json.dumps(meta), eid))
            for code in (200, 429, 503, None):
                m = dict(meta, web_resource={'status_code': code})
                cur = con.execute('INSERT INTO events(host_id,harness,agent_name,event_type,severity,message,metadata_json,created_at) VALUES(?,?,?,?,?,?,?,?)',
                    ('qa-box-01','codex','agent-reader','observed_step','INFO',f'HTTP fixture {code}',json.dumps(m),time.time()-10))
                cls.ids[str(code)] = cur.lastrowid
                con.execute('INSERT INTO event_execution(event_id,command_input,command_output,exit_code,output_truncated) VALUES(?,?,?,?,0)', (cur.lastrowid, 'curl https://example.test', '', 6 if code is None else 0))
    _seed = classmethod(fixtures.LiveReadabilityBrowserTests._seed.__func__)
    tearDownClass = classmethod(fixtures.LiveReadabilityBrowserTests.tearDownClass.__func__)
    login_and_open = fixtures.LiveReadabilityBrowserTests.login_and_open
    assert_clean = fixtures.LiveReadabilityBrowserTests.assert_clean

    def test_filters_exports_bookmark_and_invalid_parameters(self):
        for width, height, mobile in ((1440,900,False),(390,844,True)):
            with self.subTest(mobile=mobile):
                pg = self.browser.new_page(width,height,mobile)
                self.addCleanup(pg.close)
                self.login_and_open(pg, f"event:{self.ids['curl_401']}")
                params = {'host':'qa-box-01','prog':'curl','source':'observed_step','from_ts':self.bounds[0], 'to_ts':self.bounds[1], 'event':f"event:{self.ids['curl_401']}",'http':'4xx'}
                pg.goto(self.srv.base_url+'/live?'+urlencode(params))
                pg.wait("document.querySelectorAll('#rows tr[data-key]').length === 2", what='two 4xx rows')
                keys = pg.eval("Array.from(document.querySelectorAll('#rows tr[data-key]'), e=>e.dataset.key).sort()")
                self.assertEqual(keys, sorted([f"event:{self.ids['curl_401']}",f"event:{self.ids['429']}"]))
                url = pg.eval('location.href')
                self.assertEqual(parse_qs(urlsplit(url).query)['from_ts'], [str(self.bounds[0])])
                # Intercept generated download blobs to inspect the actual export contents.
                pg.eval("window.exports=[]; URL.createObjectURL=b=>{window.exports.push(b);return 'blob:test'}; HTMLAnchorElement.prototype.click=function(){}")
                pg.click('#export-json')
                exported = json.loads(pg.eval('window.exports[0].text()'))
                self.assertEqual(sorted(r['http_status'] for r in exported['records']), [401,429])
                pg.click('#export-csv')
                csv = pg.eval('window.exports[1].text()')
                self.assertIn('http_status',csv)
                self.assertEqual(len(csv.splitlines()),3)
                # A new browser context has no prior cookies or local storage.
                fresh = self.browser.new_page(width,height,mobile)
                self.addCleanup(fresh.close)
                self.login_and_open(fresh, f"event:{self.ids['curl_401']}")
                fresh.goto(url)
                fresh.wait("document.querySelectorAll('#rows tr[data-key]').length === 2")
                self.assertEqual(fresh.eval("Array.from(document.querySelectorAll('#rows tr[data-key]'), e=>e.dataset.key).sort()"), keys)
                fresh.goto(self.srv.base_url+'/live?http=5xx&prog=curl')
                fresh.wait("document.querySelectorAll('#rows tr[data-key]').length === 1")
                self.assertIn('503',fresh.eval("document.querySelector('#rows').innerText"))
                fresh.goto(self.srv.base_url+'/live?http=429&prog=curl')
                fresh.wait("document.querySelectorAll('#rows tr[data-key]').length === 1")
                self.assertIn('429',fresh.eval("document.querySelector('#rows').innerText"))
                fresh.goto(self.srv.base_url+'/live?http=999&from_ts=bad&event=bad&q=token%3Dfake-test-secret&unknown=value&from=%2F%3Ftoken%3Dfake-return-secret')
                fresh.wait("document.querySelectorAll('#rows tr[data-key]').length > 3")
                query=fresh.eval('location.search')
                for value in ('999','bad','fake-test-secret','unknown','fake-return-secret'):
                    self.assertNotIn(value,query)
                self.assert_clean(fresh, 'invalid filters')

    def test_older_pages_keep_http_selection(self):
        with sqlite3.connect(self.srv.db_path) as con:
            for i in range(510):
                con.execute('INSERT INTO events(host_id,harness,agent_name,event_type,severity,message,metadata_json,created_at) VALUES(?,?,?,?,?,?,?,?)',
                    ('history-host','codex','agent-reader','observed_step','INFO',f'Page padding {i}',json.dumps({'action':'shell','program':'curl','web_resource':{'status_code':200}}),time.time()+i))
            old = con.execute('INSERT INTO events(host_id,harness,agent_name,event_type,severity,message,metadata_json,created_at) VALUES(?,?,?,?,?,?,?,?)',
                ('history-host','codex','agent-reader','observed_step','INFO','Old failed HTTP request',json.dumps({'action':'shell','program':'curl','web_resource':{'status_code':401}}),time.time()-86400)).lastrowid
        pg = self.browser.new_page(1440,900,False)
        self.addCleanup(pg.close)
        self.login_and_open(pg, '')
        pg.goto(self.srv.base_url+'/live?http=4xx&host=history-host')
        pg.wait("document.querySelector('#load-older') && !document.querySelector('#load-older').classList.contains('hidden')")
        for _ in range(4):
            if pg.eval("!!document.querySelector('#rows tr[data-key=\"event:%s\"]')" % old):
                break
            pg.click('#load-older')
            pg.wait("!document.querySelector('#load-older').disabled")
        pg.wait("!!document.querySelector('#rows tr[data-key=\"event:%s\"]')" % old)
        self.assertEqual(pg.eval("Array.from(document.querySelectorAll('#rows tr[data-key]'),e=>e.dataset.key)"), [f'event:{old}'])
