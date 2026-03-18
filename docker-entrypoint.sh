#!/bin/sh
# Atualiza templates nuclei em background para não travar o startup
nuclei -ut -silent &>/tmp/nuclei-update.log &
exec "$@"
