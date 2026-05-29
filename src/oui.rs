static OUI_TABLE: &[(&str, &str)] = &[
    // Apple
    ("0017F2", "Apple"),
    ("001CB3", "Apple"),
    ("002332", "Apple"),
    ("002500", "Apple"),
    ("0026BB", "Apple"),
    ("3C0754", "Apple"),
    ("40A6D9", "Apple"),
    ("60F81D", "Apple"),
    ("680927", "Apple"),
    ("7C6D62", "Apple"),
    ("843835", "Apple"),
    ("8C2937", "Apple"),
    ("A45E60", "Apple"),
    ("B8FF61", "Apple"),
    ("D4619D", "Apple"),
    ("F0B479", "Apple"),
    ("F82793", "Apple"),
    ("1865E3", "Apple"),
    ("3C22FB", "Apple"),
    ("70EC4D", "Apple"),
    ("9C29A8", "Apple"),
    ("C82A14", "Apple"),
    ("E898C8", "Apple"),
    // Samsung
    ("001247", "Samsung"),
    ("002637", "Samsung"),
    ("2CAE2B", "Samsung"),
    ("400E85", "Samsung"),
    ("5001BB", "Samsung"),
    ("8C77B3", "Samsung"),
    ("A00798", "Samsung"),
    ("CC07AB", "Samsung"),
    ("D0172F", "Samsung"),
    ("F8042E", "Samsung"),
    ("3CA10D", "Samsung"),
    ("701CE7", "Samsung"),
    ("8CF5A3", "Samsung"),
    // Intel
    ("0002B3", "Intel"),
    ("0016EA", "Intel"),
    ("002314", "Intel"),
    ("14ABC5", "Intel"),
    ("38DEAD", "Intel"),
    ("8C8D28", "Intel"),
    ("ACFDCE", "Intel"),
    ("D85D4C", "Intel"),
    ("4CBB58", "Intel"),
    // Cisco
    ("00000C", "Cisco"),
    ("000164", "Cisco"),
    ("001AA2", "Cisco"),
    ("001B54", "Cisco"),
    ("001F9E", "Cisco"),
    ("34BDFA", "Cisco"),
    ("6886A7", "Cisco"),
    ("F472EA", "Cisco"),
    ("00E0F7", "Cisco"),
    ("0019AA", "Cisco"),
    // Huawei
    ("001882", "Huawei"),
    ("001E10", "Huawei"),
    ("04C06F", "Huawei"),
    ("286ED4", "Huawei"),
    ("48DB50", "Huawei"),
    ("54890C", "Huawei"),
    ("94DB56", "Huawei"),
    ("AC61EA", "Huawei"),
    ("2C9D1E", "Huawei"),
    ("687F74", "Huawei"),
    // TP-Link
    ("14CC20", "TP-Link"),
    ("1C3BF3", "TP-Link"),
    ("50C7BF", "TP-Link"),
    ("60A4B7", "TP-Link"),
    ("74DA38", "TP-Link"),
    ("B0487A", "TP-Link"),
    ("D8EB97", "TP-Link"),
    ("F81A67", "TP-Link"),
    ("A42BB0", "TP-Link"),
    // Netgear
    ("00095B", "Netgear"),
    ("001B2F", "Netgear"),
    ("0026F2", "Netgear"),
    ("202BC1", "Netgear"),
    ("A021B7", "Netgear"),
    ("C03F0E", "Netgear"),
    ("2C3033", "Netgear"),
    // Raspberry Pi Foundation
    ("B827EB", "Raspberry Pi"),
    ("DCA632", "Raspberry Pi"),
    ("E45F01", "Raspberry Pi"),
    // Google
    ("F4F5E8", "Google"),
    ("3C5AB4", "Google"),
    ("54607E", "Google"),
    ("A47733", "Google"),
    ("1C3ADE", "Google"),
    // Amazon
    ("FC65DE", "Amazon"),
    ("747548", "Amazon"),
    ("34D270", "Amazon"),
    ("A002DC", "Amazon"),
    ("F0272D", "Amazon"),
    // Microsoft
    ("00125A", "Microsoft"),
    ("281878", "Microsoft"),
    ("485073", "Microsoft"),
    ("7C1E52", "Microsoft"),
    ("28187F", "Microsoft"),
    // Xiaomi
    ("28E31F", "Xiaomi"),
    ("642737", "Xiaomi"),
    ("8C97EA", "Xiaomi"),
    ("AC2374", "Xiaomi"),
    ("F48B32", "Xiaomi"),
    ("0CF3EE", "Xiaomi"),
    ("7851CE", "Xiaomi"),
    // ASUS
    ("001E8C", "ASUS"),
    ("107B44", "ASUS"),
    ("2C56DC", "ASUS"),
    ("5404A6", "ASUS"),
    ("BC9746", "ASUS"),
    ("04D4C4", "ASUS"),
    // LG
    ("001E75", "LG"),
    ("10683F", "LG"),
    ("40B0FA", "LG"),
    ("6CD0CF", "LG"),
    // Sony
    ("0013A9", "Sony"),
    ("30170C", "Sony"),
    ("54421A", "Sony"),
    ("AC9B0A", "Sony"),
    ("001A80", "Sony"),
    // Linksys
    ("00045A", "Linksys"),
    ("001217", "Linksys"),
    ("001839", "Linksys"),
    ("001A70", "Linksys"),
    ("002369", "Linksys"),
    // D-Link
    ("00055D", "D-Link"),
    ("000D88", "D-Link"),
    ("001CF0", "D-Link"),
    ("1CBDB9", "D-Link"),
    ("C8BE19", "D-Link"),
    ("14D64D", "D-Link"),
    // Qualcomm / Atheros
    ("001374", "Qualcomm"),
    ("00237A", "Qualcomm"),
    ("64BC0C", "Qualcomm"),
    ("0026B9", "Qualcomm"),
    // Broadcom
    ("001018", "Broadcom"),
    ("001A73", "Broadcom"),
    ("286ED4", "Broadcom"),
    // Dell
    ("001422", "Dell"),
    ("001EC9", "Dell"),
    ("BCF1F2", "Dell"),
    ("F0272D", "Dell"),
    // HP / HPE
    ("0001E6", "HP"),
    ("001708", "HP"),
    ("001CC4", "HP"),
    ("3C4A92", "HP"),
    // Aruba / HPE
    ("001A1E", "Aruba"),
    ("70883B", "Aruba"),
    ("24DEC6", "Aruba"),
    // MediaTek
    ("000C43", "MediaTek"),
    ("4C9EFF", "MediaTek"),
    ("00BB60", "MediaTek"),
    // Realtek
    ("001E64", "Realtek"),
    ("00E04C", "Realtek"),
    ("788CB5", "Realtek"),
    // OnePlus
    ("741BB4", "OnePlus"),
    ("A052B4", "OnePlus"),
];

pub fn lookup(mac: &str) -> &'static str {
    let upper = mac.to_uppercase().replace(':', "");
    if upper.len() < 6 {
        return "";
    }
    let prefix = &upper[..6];
    for (oui, name) in OUI_TABLE {
        if *oui == prefix {
            return name;
        }
    }
    ""
}
