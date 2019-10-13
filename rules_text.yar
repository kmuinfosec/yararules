rule XML
{
    strings:
        $xml_hex = {3C 3F 78 6D 6C 20 76 65 72 73 69 6F 6E 3D}

   condition:
        $xml_hex
}

rule PHP{
    strings:
        $php_tag_hex = {3C 3F 70 68 70}
    condition:
        $php_tag_hex
}

rule HTML
{
    strings:
        $html_hex = {3C 21 44 4F 43 54 59 50 45 20 68 74 6D 6C}
        $html_hex_2 = {3C 21 64 6F 63 74 79 70 65 20 68 74 6D 6C}
        $html_hex_3 = {3C 21 44 4F 43 54 59 50 45 20 48 54 4D 4C}
        $html_hex_4 = {3C 68 74 6D 6C}
    condition:
        $html_hex or $html_hex_2 or $html_hex_3 or $html_hex_4
}