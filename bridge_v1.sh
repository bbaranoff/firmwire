#!/usr/bin/env bash
# bridge_v1.sh - premiere version, la plus simple, du montage Shannon + traducteur DSP + C54x.
# Cable ce qui marche aujourd'hui (coeur valide) et marque explicitement ce qui est encore en retro.
#
# CE QUI PASSE (actif dans cette v1):
#   - FirmWire boote le modem Shannon G973F (SoC S5000AP) jusqu'au regime etabli.
#   - BridgeDSPPeripheral (CALYPSO_BRIDGE=1) remplace le bouchon DSP : satisfait le handshake
#     de sync (141/286), modelise la file DSP->ARM (head 0x64 / tail 0x66 / entrees 0x68),
#     et porte un client C54x BSP (UDP 6702, en-tete 8o + 148 bits, format pont/trx.py).
#   - Log complet du dialogue DSP (--debug-peripheral DSPPeripheral).
#
# CE QUI EST ENCORE EN RETRO (place tenue, TODO ci-dessous):
#   - Trigger 2G : forcer UE_RAT_MODE_CAPA en GSM-only, via NV (--shannon-loader-nv-data)
#     ou commande AT (ATI, AT+COPS / AT+MODECHAN) feedee par le canal SIPC fmt. Gate: framing IPC.
#   - Traduction des taches FB/SB/TCH : encodage commande Shannon <-> tache TI C54x. Gate: rapport Ghidra.
#   - Chaine radio osmo (osmo-bts-trx <-> pont_dsp.py <-> C54x <-> reseau) pour la source du LOC UPD ACCEPT.
set -euo pipefail

FW_DIR="${FW_DIR:-/opt/GSM/FirmWire}"
IMG="${IMG:-/opt/GSM/FirmWire/.v1/modem.tar.md5.lz4}"
WS="${WS:-SCRATCH}"
TIMEOUT="${TIMEOUT:-240}"
LOG="${LOG:-/opt/GSM/FirmWire/.v1/bridge_v1.log}"

mkdir -p "$(dirname "$LOG")"

echo "[v1] Shannon + pont DSP (C54x) - coeur valide"
echo "[v1] image : $IMG"
echo "[v1] log   : $LOG"

# --- TODO trigger 2G (decommenter quand le lever est pret) --------------------
# Option NV: crafter un NV_DATA.bin avec PSS.MMC.UE_RAT_MODE_CAPA = GSM-only puis:
#   NV_ARG="--shannon-loader-nv-data /opt/GSM/FirmWire/.v1/nv_gsm_only.bin"
# Option AT: apres boot, feeder "AT+COPS=..."/"AT+MODECHAN=..." dans le canal SIPC fmt (CP recv).
NV_ARG="${NV_ARG:-}"

# --- lancement du coeur valide ------------------------------------------------
docker run --rm \
  -e CALYPSO_BRIDGE=1 \
  -e CALYPSO_DSP_PORT="${CALYPSO_DSP_PORT:-6702}" \
  -v "$FW_DIR":/firmwire \
  -v "$(dirname "$IMG")":/img \
  firmwire bash -c "timeout ${TIMEOUT} python3 ./firmwire.py /img/$(basename "$IMG") \
      --workspace ${WS} ${NV_ARG} \
      --debug-peripheral DSPPeripheral 2>&1" | tee "$LOG"

echo "[v1] termine. Taches DSP vues :"
grep -aE "DSP_WR_off|RING_|DSP_SYNC" "$LOG" | grep -avE "<- 00000000" | tail -20 || true
