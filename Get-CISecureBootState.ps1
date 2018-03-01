# enklaste testet.
# man testar alltid efter något som ska vara sant, såklart. hade varit orimligt att leta efter alla möjliga felinställningar.

if (Confirm-SecureBootUEFI) {
    return $true
}