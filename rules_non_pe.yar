rule PDF
{
    strings:
        $pdf_re = /^%PDF-1.[0-9]*/
        $pdf_re_2 = /^%PDF-v-1.[0-9]*/
    condition:
        $pdf_re or $pdf_re_2
}

rule XML
{
    strings:
        $xml_hex = {3C 3F 78 6D 6C 20 76 65 72 73 69 6F 6E 3D}

   condition:
        $xml_hex
}

rule RAR
{
    strings:
        $rar_hex = {52 61 72 21 1A 07 00}
        $rar_hex_2 = {52 61 72 21 1A 07 01 00}
    condition:
        $rar_hex or $rar_hex_2
}

rule HWP
{
    strings:
        $hwp_header = {D0 CF 11 E0 A1 B1 1A E1}
        $hwp_hex_old = {48 57 50 20 44 6F 63 75 6D 6E 74 20 46 69 6C 65}
        $hwp_hex_new = {48 57 50 20 44 6F 63 75 6D 65 6E 74 20 46 69 6C 65}
    condition:
        $hwp_header and ($hwp_hex_old or $hwp_hex_new)
}

rule WOFF{
    strings:
        $woff_header = {77 4F 46 46}
    condition:
        $woff_header
}

rule WOFF2{
    strings:
        $woff2_header = {77 4F 46 32}
    condition:
        $woff2_header
}

rule MACH_O64{
    strings:
        $mach_o_64_hex = {CF FA ED FE}
    condition:
        $mach_o_64_hex
}

rule PYC2{
    strings:
        $pyc_20_hex = {87 C6 0D 0A}
        $pyc_21_hex = {2A EB 0D 0A}
        $pyc_22_hex = {2D ED 0D 0A}
        $pyc_23_hex = {31 F2 0D 0A}
        $pyc_24_hex = {6D F2 0D 0A}
        $pyc_25_hex = {B3 F2 0D 0A}
        $pyc_26_hex = {D1 F2 0D 0A}
        $pyc_27_hex = {03 F3 0D 0A}
    condition:
        $pyc_20_hex or $pyc_21_hex or $pyc_22_hex or $pyc_23_hex or $pyc_24_hex or $pyc_25_hex or $pyc_26_hex or $pyc_27_hex
}

rule PYC3{
    strings:
        $pyc_30_hex = {3B 0C 0D 0A}
        $pyc_31_hex = {4F 0C 0D 0A}
        $pyc_32_hex = {6C 0C 0D 0A}
        $pyc_33_hex = {9E 0C 0D 0A}
        $pyc_34_hex = {EE 0C 0D 0A}
        $pyc_35_hex = {16 0D 0D 0A}
    condition:
        $pyc_30_hex or $pyc_31_hex or $pyc_32_hex or $pyc_33_hex or $pyc_34_hex or $pyc_35_hex
}