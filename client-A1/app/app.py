#!/usr/bin/env python3
"""Servizio HTTP di client-A1 (Site 1).

Programma scelto per il confinamento AppArmor: un servizio esposto di rete su
un dispositivo "sensitive" (traccia NSD 2025-26, VPN Site 1). Gli endpoint
/secrets e /etcwrite sono hook di test espliciti che simulano le prime azioni
tipiche di un processo compromesso: leggere lo store di credenziali del sistema
e manomettere la configurazione. Sotto profilo attivo producono le righe di
DENIED per l'evidenza del report.

Esecuzione confinata (da init.sh):
    aa-exec -p client-a1-app -- python3 /opt/client-a1/app.py
"""

import os
from http.server import BaseHTTPRequestHandler, HTTPServer

DATA_DIR = "/opt/client-a1/data"
STATUS_FILE = os.path.join(DATA_DIR, "status.txt")
PORT = 8080


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, html):
        body = html.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _page(self, title, lines):
        rows = "".join("<li>{}</li>".format(l) for l in lines)
        return ("<html><head><title>{}</title></head><body><h1>{}</h1>"
                "<ul>{}</ul></body></html>".format(title, title, rows))

    def do_GET(self):
        if self.path == "/":
            # azione CONSENTITA: il servizio legge solo i propri dati
            try:
                with open(STATUS_FILE) as f:
                    status = f.read().strip()
            except OSError as e:
                self._send(500, self._page("client-A1",
                                           ["errore lettura stato: {}".format(e)]))
                return
            self._send(200, self._page("client-A1", [
                "stato: {}".format(status),
                "profilo AppArmor attivo: client-a1-app (enforce)",
            ]))

        elif self.path == "/secrets":
            # azione VIETATA (obiettivo 1: credenziali OS)
            try:
                with open("/etc/shadow") as f:
                    f.read()
                # raggiunto SOLO se il profilo non e' attivo: segnalarlo
                self._send(200, self._page("client-A1", [
                    "ATTENZIONE: /etc/shadow LEGGIBILE — profilo non attivo!",
                ]))
            except OSError as e:
                self._send(500, self._page("Accesso negato",
                                           ["/etc/shadow: {}".format(e)]))

        elif self.path == "/etcwrite":
            # azione VIETATA (obiettivo 3: integrita' di /etc)
            try:
                with open("/etc/client-a1-pwned", "w") as f:
                    f.write("compromesso\n")
                self._send(200, self._page("client-A1", [
                    "ATTENZIONE: scrittura in /etc RIUSCITA — profilo non attivo!",
                ]))
            except OSError as e:
                self._send(500, self._page("Scrittura negata",
                                           ["/etc/client-a1-pwned: {}".format(e)]))

        else:
            self._send(404, "<html><body><h1>404</h1></body></html>")

    def log_message(self, fmt, *args):
        print("[client-a1-app]", self.address_string(), fmt % args, flush=True)


def main():
    srv = HTTPServer(("0.0.0.0", PORT), Handler)
    print("[client-a1-app] in ascolto su :{}".format(PORT), flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
