# Spicy-based HTTP protocol analyzer

spicy_add_analyzer(
    NAME Zeek::HTTP_Spicy
    SOURCES http.spicy
    EVENTS http.evt
    PROTOCOLS TCP
)
