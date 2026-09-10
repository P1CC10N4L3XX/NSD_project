#!/bin/bash
set -eu

CA_CN="${CA_CN:-NSD_project}"
EASYRSA_DIR="/usr/share/easy-rsa"
OPENVPN_BASE="/root/openvpn"
SERVER_NAME="CE3"
CLIENTS="CE1 CE2"

PKI_DIR="${EASYRSA_DIR}/pki"

cd "${EASYRSA_DIR}"

if [ -d "${PKI_DIR}" ] && [ -f "${PKI_DIR}/ca.crt" ] && [ -f "${PKI_DIR}/issued/${SERVER_NAME}.crt" ] && [ -f "${PKI_DIR}/private/${SERVER_NAME}.key" ]; then
    echo "PKI directory already exists. Skipping PKI generation."
else
    export EASYRSA_BATCH=1
    export EASYRSA_REQ_CN="${CA_CN}"

    ./easyrsa init-pki
    ./easyrsa build-ca nopass
    ./easyrsa build-server-full "${SERVER_NAME}" nopass

    for CLIENT in ${CLIENTS}; do
        ./easyrsa build-client-full "${CLIENT}" nopass
    done

    ./easyrsa gen-dh
fi

mkdir -p "${OPENVPN_BASE}/keys" "${OPENVPN_BASE}/export/CE1" "${OPENVPN_BASE}/export/CE2"

cp -f "${PKI_DIR}/ca.crt" "${OPENVPN_BASE}/keys/ca.crt"
cp -f "${PKI_DIR}/issued/${SERVER_NAME}.crt" "${OPENVPN_BASE}/keys/${SERVER_NAME}.crt"
cp -f "${PKI_DIR}/private/${SERVER_NAME}.key" "${OPENVPN_BASE}/keys/${SERVER_NAME}.key"
cp -f "${PKI_DIR}/dh.pem" "${OPENVPN_BASE}/keys/dh.pem"


for CLIENT in ${CLIENTS}; do
    mkdir -p "${OPENVPN_BASE}/export/${CLIENT}"
    cp -f "${PKI_DIR}/ca.crt" "${OPENVPN_BASE}/export/${CLIENT}/ca.crt"
    cp -f "${PKI_DIR}/issued/${CLIENT}.crt" "${OPENVPN_BASE}/export/${CLIENT}/${CLIENT}.crt"
    cp -f "${PKI_DIR}/private/${CLIENT}.key" "${OPENVPN_BASE}/export/${CLIENT}/${CLIENT}.key"
done

echo "PKI generation completed. Certificates and keys are stored in ${OPENVPN_BASE}/keys and ${OPENVPN_BASE}/export."