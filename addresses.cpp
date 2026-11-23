#include <windows.h>
#include "addresses.h"

bool g_IsSteam = false;

JC4NativeBuild IdentifyJC4NativeBuild(uintptr_t exeBase) {
    if (!exeBase) return JC4NativeBuild::Unknown;
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(exeBase);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < sizeof(IMAGE_DOS_HEADER) ||
        dos->e_lfanew > 0x1000 - sizeof(IMAGE_NT_HEADERS64)) return JC4NativeBuild::Unknown;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(exeBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return JC4NativeBuild::Unknown;
    const auto& h = nt->OptionalHeader;
    const auto timestamp = nt->FileHeader.TimeDateStamp;
    if (h.SizeOfImage == 0x10c02000 && h.AddressOfEntryPoint == 0x10bde020 && timestamp == 0x5d55d332)
        return JC4NativeBuild::Steam;
    if (h.SizeOfImage == 0x1b2a8000 && h.AddressOfEntryPoint == 0x1b284020 && timestamp == 0x62151540)
        return JC4NativeBuild::Epic;
    return JC4NativeBuild::Unknown;
}

uintptr_t g_Addr_78840;
uintptr_t g_Addr_78F10;
uintptr_t g_Addr_88850;
uintptr_t g_Addr_F3660;
uintptr_t g_Addr_1B8810;
uintptr_t g_Addr_1D1640;
uintptr_t g_Addr_1D1877;
uintptr_t g_Addr_1D1888;
uintptr_t g_Addr_1D189E;
uintptr_t g_Addr_1D18C5;
uintptr_t g_Addr_244860;
uintptr_t g_Addr_246470;
uintptr_t g_Addr_2530B0;
uintptr_t g_Addr_253E20;
uintptr_t g_Addr_283E70;
uintptr_t g_Addr_28F0A0;
uintptr_t g_Addr_286930;
uintptr_t g_Addr_2AC6E0;
uintptr_t g_Addr_322720;
uintptr_t g_Addr_406CC9;
uintptr_t g_Addr_422D60;
uintptr_t g_Addr_422F0A;
uintptr_t g_Addr_422F12;
uintptr_t g_Addr_423030;
uintptr_t g_Addr_4230D0;
uintptr_t g_Addr_4235BC;
uintptr_t g_Addr_4235C5;
uintptr_t g_Addr_423655;
uintptr_t g_Addr_424310;
uintptr_t g_Addr_4246E0;
uintptr_t g_Addr_424910;
uintptr_t g_Addr_42AE40;
uintptr_t g_Addr_46F2D5;
uintptr_t g_Addr_4715D0;
uintptr_t g_Addr_471790;
uintptr_t g_Addr_480240;
uintptr_t g_Addr_48F5E0;
uintptr_t g_Addr_4E6DA0;
uintptr_t g_Addr_53C0A0;
uintptr_t g_Addr_53D7B0;
uintptr_t g_Addr_53DF40;
uintptr_t g_Addr_542110;
uintptr_t g_Addr_5509E0;
uintptr_t g_Addr_5570D0;
uintptr_t g_Addr_5722C0;
uintptr_t g_Addr_573520;
uintptr_t g_Addr_574350;
uintptr_t g_Addr_578F60;
uintptr_t g_Addr_594D00;
uintptr_t g_Addr_6A7630;
uintptr_t g_Addr_6CFBB4;
uintptr_t g_Addr_6CFBB9;
uintptr_t g_Addr_6DE0C0;
uintptr_t g_Addr_6F7F40;
uintptr_t g_Addr_702857;
uintptr_t g_Addr_70288F;
uintptr_t g_Addr_761BE0;
uintptr_t g_Addr_761C30;
uintptr_t g_Addr_761CE0;
uintptr_t g_Addr_7B3200;
uintptr_t g_Addr_7EAC10;
uintptr_t g_Addr_7F6290;
uintptr_t g_Addr_7FE8CC;
uintptr_t g_Addr_86D5B9;
uintptr_t g_Addr_8F0E40;
uintptr_t g_Addr_91C920;
uintptr_t g_Addr_955940;
uintptr_t g_Addr_AFD360;
uintptr_t g_Addr_ABDFF7;
uintptr_t g_Addr_ABE007;
uintptr_t g_Addr_B28D30;
uintptr_t g_Addr_B7F570;
uintptr_t g_Addr_B80530;
uintptr_t g_Addr_B89A10;
uintptr_t g_Addr_B8A890;
uintptr_t g_Addr_BADC60;
uintptr_t g_Addr_C3F540;
uintptr_t g_Addr_CB1790;
uintptr_t g_Addr_CF27D0;
uintptr_t g_Addr_CD23C0;
uintptr_t g_Addr_CD2D20;
uintptr_t g_Addr_D75D70;
uintptr_t g_Addr_E15C10;
uintptr_t g_Addr_EB4D00;
uintptr_t g_Addr_FD13A0;
uintptr_t g_Addr_1AF9274;
uintptr_t g_Addr_1CAE1C4;
uintptr_t g_Addr_1CAE1CC;
uintptr_t g_Addr_1CB8220;
uintptr_t g_Addr_1CCB620;
uintptr_t g_Addr_1D083E0;
uintptr_t g_Addr_1D139E8;
uintptr_t g_Addr_1D25450;
uintptr_t g_Addr_1D7DF98;
uintptr_t g_Addr_1D7E0E8;
uintptr_t g_Addr_1E01E14;
uintptr_t g_Addr_1E7EEC0;
uintptr_t g_Addr_2AD0F3C;
uintptr_t g_Addr_2AD4492;
uintptr_t g_Addr_2AD4500;
uintptr_t g_Addr_2AD6850;
uintptr_t g_Addr_2AE2760;
uintptr_t g_Addr_2AE55F0;
uintptr_t g_Addr_2AE55F8;
uintptr_t g_Addr_2AE55F9;
uintptr_t g_Addr_2AE5610;
uintptr_t g_Addr_2AE9720;
uintptr_t g_Addr_2AE9818;
uintptr_t g_Addr_2AEAD0C;
uintptr_t g_Addr_2AEAD10;
uintptr_t g_Addr_2AF1E64;
uintptr_t g_Addr_2AF1E68;
uintptr_t g_Addr_2C73AE0;
uintptr_t g_Addr_2C846B0;
uintptr_t g_Addr_2C84BE8;
uintptr_t g_Addr_2CAD92D;
uintptr_t g_Addr_2CADA68;
uintptr_t g_Addr_2CAFD90;
uintptr_t g_Addr_2CAF970;
uintptr_t g_Addr_2CAFA50;
uintptr_t g_Addr_2CAFDB0;
uintptr_t g_Addr_2CB0A48;
uintptr_t g_Addr_2CB1938;
uintptr_t g_Addr_2CB1D20;
uintptr_t g_Addr_2CB1D38;
uintptr_t g_Addr_2CB1D90;
uintptr_t g_Addr_2CB1D98;
uintptr_t g_Addr_2CB2388;
uintptr_t g_Addr_2CB4B28;
uintptr_t g_Addr_2CB4B30;
uintptr_t g_Addr_2CB80F8;
uintptr_t g_Addr_2CB5C70;
uintptr_t g_Addr_2CB5ED0;
uintptr_t g_Addr_2CB9CB0;
uintptr_t g_Addr_2CB9CB8;
uintptr_t g_Addr_2CE3F30;
uintptr_t g_Addr_2CE3F38;
uintptr_t g_Addr_6000000;
uintptr_t g_Addr_75C5E60;
uintptr_t g_Addr_7600060;
uintptr_t g_Addr_76014E0;
uintptr_t g_Addr_77B4BFB;
uintptr_t g_Addr_77BCA70;
uintptr_t g_Addr_77BCBDD;
uintptr_t g_Addr_77BDE85;
uintptr_t g_Addr_77BE2FE;
uintptr_t g_Addr_77BE4A6;
uintptr_t g_Addr_77BE5A5;
uintptr_t g_Addr_77BE81D;
uintptr_t g_Addr_79AFC53;
uintptr_t g_Addr_7B0B340;
uintptr_t g_Addr_7B0C3D0;
uintptr_t g_Addr_8354F40;
uintptr_t g_Addr_8FEEF70;
uintptr_t g_Addr_91CA540;
uintptr_t g_Addr_92004C0;
uintptr_t g_Addr_98AA180;
uintptr_t g_Addr_98AAE20;
uintptr_t g_Addr_98AAE3B;
uintptr_t g_Addr_98AAED1;
uintptr_t g_Addr_98ABC9B;
uintptr_t g_Addr_98ABCE5;
uintptr_t g_Addr_98ABD17;
uintptr_t g_Addr_9F8E980;
uintptr_t g_Addr_9FEC432;
uintptr_t g_Addr_9FED7B9;
uintptr_t g_Addr_9FED943;
uintptr_t g_Addr_A369860;
uintptr_t g_Addr_A59C196;
uintptr_t g_Addr_A6CA200;
uintptr_t g_Addr_A6BCD30;
uintptr_t g_Addr_10000000;
uintptr_t g_Addr_10C02000;
uintptr_t g_Addr_10E8544;
uintptr_t g_Addr_2C84450;
uintptr_t g_Addr_2C84458;
uintptr_t g_Addr_F8B8B0;
uintptr_t g_Addr_F8BDC0;
uintptr_t g_Addr_F27DB0;
uintptr_t g_Addr_B8F4E0;
uintptr_t g_Addr_2CCB738;
uintptr_t g_Addr_E862E0;
uintptr_t g_Addr_825A60;
uintptr_t g_Addr_EAD660;
uintptr_t g_Addr_EAE540;
uintptr_t g_Addr_7B3A50;
uintptr_t g_Addr_7B6D10;
uintptr_t g_Addr_B478E0;
uintptr_t g_Addr_A8D8D0;
uintptr_t g_Addr_27C250;
uintptr_t g_Addr_2CA54D8;
uintptr_t g_Addr_17C690;
uintptr_t g_Addr_286040;
uintptr_t g_Addr_2862F0;
uintptr_t g_Addr_550930;
uintptr_t g_Addr_52CF20;
uintptr_t g_Addr_571AC0;

void InitializePlatformAddresses() {
    const auto build = IdentifyJC4NativeBuild(reinterpret_cast<uintptr_t>(GetModuleHandleA(nullptr)));
    g_IsSteam = build == JC4NativeBuild::Steam ||
                (build == JC4NativeBuild::Unknown && GetModuleHandleA("steam_api64.dll") != nullptr);
    g_Addr_78840 = g_IsSteam ? 0x78840u : 0x78280u;
    g_Addr_78F10 = g_IsSteam ? 0x78F10u : 0x78F10u;
    g_Addr_88850 = g_IsSteam ? 0x88850u : 0x882F0u;
    g_Addr_F3660 = g_IsSteam ? 0xF3660u : 0xF3520u;
    g_Addr_1B8810 = g_IsSteam ? 0x1B8810u : 0x1B8FE0u;
    g_Addr_1D1640 = g_IsSteam ? 0x1D1640u : 0x1D2060u;
    g_Addr_1D1877 = g_IsSteam ? 0x1D1877u : 0x1D2297u;
    g_Addr_1D1888 = g_IsSteam ? 0x1D1888u : 0x1D22A8u;
    g_Addr_1D189E = g_IsSteam ? 0x1D189Eu : 0x1D22BEu;
    g_Addr_1D18C5 = g_IsSteam ? 0x1D18C5u : 0x1D22E5u;
    g_Addr_244860 = g_IsSteam ? 0x244860u : 0x245360u;
    g_Addr_246470 = g_IsSteam ? 0x246470u : 0x4613591u;
    g_Addr_2530B0 = g_IsSteam ? 0x2530B0u : 0x253DE0u;
    g_Addr_253E20 = g_IsSteam ? 0x253E20u : 0x254B50u;
    g_Addr_283E70 = g_IsSteam ? 0x283E70u : 0x283E70u;
    g_Addr_28F0A0 = g_IsSteam ? 0x28F0A0u : 0x28F0A0u;
    g_Addr_286930 = g_IsSteam ? 0x286930u : 0x287680u;
    g_Addr_2AC6E0 = g_IsSteam ? 0x2AC6E0u : 0x486C910u;
    g_Addr_322720 = g_IsSteam ? 0x322720u : 0x324070u;
    g_Addr_406CC9 = g_IsSteam ? 0x406CC9u : 0x4085C9u;
    g_Addr_422D60 = g_IsSteam ? 0x422D60u : 0x424A50u;
    g_Addr_422F0A = g_IsSteam ? 0x422F0Au : 0x424BFAu;
    g_Addr_422F12 = g_IsSteam ? 0x422F12u : 0x424C02u;
    g_Addr_423030 = g_IsSteam ? 0x423030u : 0x424D20u;
    g_Addr_4230D0 = g_IsSteam ? 0x4230D0u : 0x424DC0u;
    g_Addr_4235BC = g_IsSteam ? 0x4235BCu : 0x4252ACu;
    g_Addr_4235C5 = g_IsSteam ? 0x4235C5u : 0x4252B5u;
    g_Addr_423655 = g_IsSteam ? 0x423655u : 0x425345u;
    g_Addr_424310 = g_IsSteam ? 0x424310u : 0x426050u;
    g_Addr_4246E0 = g_IsSteam ? 0x4246E0u : 0x426420u;
    g_Addr_424910 = g_IsSteam ? 0x424910u : 0x426650u;
    g_Addr_42AE40 = g_IsSteam ? 0x42AE40u : 0x42CC40u;
    g_Addr_46F2D5 = g_IsSteam ? 0x46F2D5u : 0x46DC35u;
    g_Addr_4715D0 = g_IsSteam ? 0x4715D0u : 0x473860u;
    g_Addr_471790 = g_IsSteam ? 0x471790u : 0x473A20u;
    g_Addr_480240 = g_IsSteam ? 0x480240u : 0x482680u;
    g_Addr_48F5E0 = g_IsSteam ? 0x48F5E0u : 0x491AE0u;
    g_Addr_4E6DA0 = g_IsSteam ? 0x4E6DA0u : 0x4E88A0u;
    g_Addr_53C0A0 = g_IsSteam ? 0x53C0A0u : 0x53C0A0u;
    g_Addr_53D7B0 = g_IsSteam ? 0x53D7B0u : 0x53F470u;
    g_Addr_53DF40 = g_IsSteam ? 0x53DF40u : 0x53FC00u;
    g_Addr_542110 = g_IsSteam ? 0x542110u : 0x543DC0u;
    g_Addr_5509E0 = g_IsSteam ? 0x5509E0u : 0x1482FC81u;
    g_Addr_5570D0 = g_IsSteam ? 0x5570D0u : 0x14842F40u;
    g_Addr_5722C0 = g_IsSteam ? 0x5722C0u : 0x5741E0u;
    g_Addr_573520 = g_IsSteam ? 0x573520u : 0x575440u;
    g_Addr_574350 = g_IsSteam ? 0x574350u : 0x148D2DA1u;
    g_Addr_578F60 = g_IsSteam ? 0x578F60u : 0x57AE60u;
    g_Addr_594D00 = g_IsSteam ? 0x594D00u : 0x596C50u;
    g_Addr_6A7630 = g_IsSteam ? 0x6A7630u : 0x6A9E70u;
    g_Addr_6CFBB4 = g_IsSteam ? 0x6CFBB4u : 0x6D2584u;
    g_Addr_6CFBB9 = g_IsSteam ? 0x6CFBB9u : 0x6D2589u;
    g_Addr_6DE0C0 = g_IsSteam ? 0x6DE0C0u : 0x6DE0C0u;
    g_Addr_6F7F40 = g_IsSteam ? 0x6F7F40u : 0x6FBAA0u;
    g_Addr_702857 = g_IsSteam ? 0x702857u : 0x7063C8u;
    g_Addr_70288F = g_IsSteam ? 0x70288Fu : 0x70640Au;
    g_Addr_761BE0 = g_IsSteam ? 0x761BE0u : 0x765B20u;
    g_Addr_761C30 = g_IsSteam ? 0x761C30u : 0x765B70u;
    g_Addr_761CE0 = g_IsSteam ? 0x761CE0u : 0x765C20u;
    g_Addr_7B3200 = g_IsSteam ? 0x7B3200u : 0x14FC3380u;
    g_Addr_7EAC10 = g_IsSteam ? 0x7EAC10u : 0x7EEE90u;
    g_Addr_7F6290 = g_IsSteam ? 0x7F6290u : 0x7FA560u;
    g_Addr_7FE8CC = g_IsSteam ? 0x7FE8CCu : 0x802FBCu;
    g_Addr_86D5B9 = g_IsSteam ? 0x86D5B9u : 0x871ED9u;
    g_Addr_8F0E40 = g_IsSteam ? 0x8F0E40u : 0x8F5CF0u;
    g_Addr_91C920 = g_IsSteam ? 0x91C920u : 0x921B10u;
    g_Addr_955940 = g_IsSteam ? 0x955940u : 0x95AD40u;
    g_Addr_AFD360 = g_IsSteam ? 0xAFD360u : 0xAFD360u;
    g_Addr_ABDFF7 = g_IsSteam ? 0xABDFF7u : 0xAC5557u;
    g_Addr_ABE007 = g_IsSteam ? 0xABE007u : 0xAC5567u;
    g_Addr_B28D30 = g_IsSteam ? 0xB28D30u : 0xB31FB0u;
    g_Addr_B7F570 = g_IsSteam ? 0xB7F570u : 0xB7F570u;
    g_Addr_B80530 = g_IsSteam ? 0xB80530u : 0xB80530u;
    g_Addr_B89A10 = g_IsSteam ? 0xB89A10u : 0xB89A10u;
    g_Addr_B8A890 = g_IsSteam ? 0xB8A890u : 0xB8A890u;
    g_Addr_BADC60 = g_IsSteam ? 0xBADC60u : 0xBB4A80u;
    g_Addr_C3F540 = g_IsSteam ? 0xC3F540u : 0xC46700u;
    g_Addr_CB1790 = g_IsSteam ? 0xCB1790u : 0xCB8D30u;
    g_Addr_CF27D0 = g_IsSteam ? 0xCF27D0u : 0xCF27D0u;
    g_Addr_CD23C0 = g_IsSteam ? 0xCD23C0u : 0xCD23C0u;
    g_Addr_CD2D20 = g_IsSteam ? 0xCD2D20u : 0xCD2D20u;
    g_Addr_D75D70 = g_IsSteam ? 0xD75D70u : 0xD7D9E0u;
    g_Addr_E15C10 = g_IsSteam ? 0xE15C10u : 0xE1D790u;
    g_Addr_EB4D00 = g_IsSteam ? 0xEB4D00u : 0xEBC980u;
    g_Addr_FD13A0 = g_IsSteam ? 0xFD13A0u : 0xFD7700u;
    g_Addr_1AF9274 = g_IsSteam ? 0x1AF9274u : 0x1B017A4u;
    g_Addr_1CAE1C4 = g_IsSteam ? 0x1CAE1C4u : 0x1CB6484u;
    g_Addr_1CAE1CC = g_IsSteam ? 0x1CAE1CCu : 0x1CB648Cu;
    g_Addr_1CB8220 = g_IsSteam ? 0x1CB8220u : 0x1CC0500u;
    g_Addr_1CCB620 = g_IsSteam ? 0x1CCB620u : 0x1CD43C0u;
    g_Addr_1D083E0 = g_IsSteam ? 0x1D083E0u : 0x1D106C0u;
    g_Addr_1D139E8 = g_IsSteam ? 0x1D139E8u : 0x1D1BC90u;
    g_Addr_1D25450 = g_IsSteam ? 0x1D25450u : 0x1D2D418u;
    g_Addr_1D7DF98 = g_IsSteam ? 0x1D7DF98u : 0x1D85EC8u;
    g_Addr_1D7E0E8 = g_IsSteam ? 0x1D7E0E8u : 0x1D86018u;
    g_Addr_1E01E14 = g_IsSteam ? 0x1E01E14u : 0x1E06C44u;
    g_Addr_1E7EEC0 = g_IsSteam ? 0x1E7EEC0u : 0x1E84B78u;
    g_Addr_2AD0F3C = g_IsSteam ? 0x2AD0F3Cu : 0x2AD7F4Cu;
    g_Addr_2AD4492 = g_IsSteam ? 0x2AD4492u : 0x2ADB3EAu;
    g_Addr_2AD4500 = g_IsSteam ? 0x2AD4500u : 0x2ADB458u;
    g_Addr_2AD6850 = g_IsSteam ? 0x2AD6850u : 0x2ADD860u;
    g_Addr_2AE2760 = g_IsSteam ? 0x2AE2760u : 0x2AE9260u;
    g_Addr_2AE55F0 = g_IsSteam ? 0x2AE55F0u : 0x2AEC04Cu;
    g_Addr_2AE55F8 = g_IsSteam ? 0x2AE55F8u : 0x2AEC054u;
    g_Addr_2AE55F9 = g_IsSteam ? 0x2AE55F9u : 0x2AEC055u;
    g_Addr_2AE5610 = g_IsSteam ? 0x2AE5610u : 0x2AEC06Cu;
    g_Addr_2AE9720 = g_IsSteam ? 0x2AE9720u : 0x2AF0138u;
    g_Addr_2AE9818 = g_IsSteam ? 0x2AE9818u : 0x2AE9818u;
    g_Addr_2AEAD0C = g_IsSteam ? 0x2AEAD0Cu : 0x2AF1774u;
    g_Addr_2AEAD10 = g_IsSteam ? 0x2AEAD10u : 0x2AF1778u;
    g_Addr_2AF1E64 = g_IsSteam ? 0x2AF1E64u : 0x2AF88C4u;
    g_Addr_2AF1E68 = g_IsSteam ? 0x2AF1E68u : 0x2AF88C8u;
    g_Addr_2C73AE0 = g_IsSteam ? 0x2C73AE0u : 0x2C79ED0u;
    g_Addr_2C846B0 = g_IsSteam ? 0x2C846B0u : 0x2C8AAA8u;
    g_Addr_2C84BE8 = g_IsSteam ? 0x2C84BE8u : 0x2C8AFD8u;
    g_Addr_2CAD92D = g_IsSteam ? 0x2CAD92Du : 0x2CAD92Du;
    g_Addr_2CADA68 = g_IsSteam ? 0x2CADA68u : 0x2CB3E48u;
    g_Addr_2CAFD90 = g_IsSteam ? 0x2CAFD90u : 0x2CB6150u;
    g_Addr_2CAF970 = g_IsSteam ? 0x2CAF970u : 0x2CB5D30u;
    g_Addr_2CAFA50 = g_IsSteam ? 0x2CAFA50u : 0x2CB5E10u;
    g_Addr_2CAFDB0 = g_IsSteam ? 0x2CAFDB0u : 0x2CB6170u;
    g_Addr_2CB0A48 = g_IsSteam ? 0x2CB0A48u : 0x2CB6E08u;
    g_Addr_2CB1938 = g_IsSteam ? 0x2CB1938u : 0x2CB7D08u;
    g_Addr_2CB1D20 = g_IsSteam ? 0x2CB1D20u : 0x2CB80F0u;
    g_Addr_2CB1D38 = g_IsSteam ? 0x2CB1D38u : 0x2CB8108u;
    g_Addr_2CB1D90 = g_IsSteam ? 0x2CB1D90u : 0x2CB8160u;
    g_Addr_2CB1D98 = g_IsSteam ? 0x2CB1D98u : 0x2CB8168u;
    g_Addr_2CB2388 = g_IsSteam ? 0x2CB2388u : 0x2CB8758u;
    g_Addr_2CB4B28 = g_IsSteam ? 0x2CB4B28u : 0x2CBAEF8u;
    g_Addr_2CB4B30 = g_IsSteam ? 0x2CB4B30u : 0x2CBAF00u;
    g_Addr_2CB80F8 = g_IsSteam ? 0x2CB80F8u : 0x2CB80F8u;
    g_Addr_2CB5C70 = g_IsSteam ? 0x2CB5C70u : 0x2CBC040u;
    g_Addr_2CB5ED0 = g_IsSteam ? 0x2CB5ED0u : 0x2CBC2A0u;
    g_Addr_2CB9CB0 = g_IsSteam ? 0x2CB9CB0u : 0x2CC1270u;
    g_Addr_2CB9CB8 = g_IsSteam ? 0x2CB9CB8u : 0x2CB9CB8u;
    g_Addr_2CE3F30 = g_IsSteam ? 0x2CE3F30u : 0x2CEA370u;
    g_Addr_2CE3F38 = g_IsSteam ? 0x2CE3F38u : 0x2CEA378u;
    g_Addr_6000000 = g_IsSteam ? 0x6000000u : 0x1B2A8000u;
    g_Addr_75C5E60 = g_IsSteam ? 0x75C5E60u : 0x3EF7EE1u;
    g_Addr_7600060 = g_IsSteam ? 0x7600060u : 0x3F48110u;
    g_Addr_76014E0 = g_IsSteam ? 0x76014E0u : 0x3F4A670u;
    g_Addr_77B4BFB = g_IsSteam ? 0x77B4BFBu : 0x419BB8Bu;
    g_Addr_77BCA70 = g_IsSteam ? 0x77BCA70u : 0x41A4AD0u;
    g_Addr_77BCBDD = g_IsSteam ? 0x77BCBDDu : 0x41A4C3Du;
    g_Addr_77BDE85 = g_IsSteam ? 0x77BDE85u : 0x41A5ED0u;
    g_Addr_77BE2FE = g_IsSteam ? 0x77BE2FEu : 0x41A6351u;
    g_Addr_77BE4A6 = g_IsSteam ? 0x77BE4A6u : 0x41A64FCu;
    g_Addr_77BE5A5 = g_IsSteam ? 0x77BE5A5u : 0x41A6602u;
    g_Addr_77BE81D = g_IsSteam ? 0x77BE81Du : 0x41A686Bu;
    g_Addr_79AFC53 = g_IsSteam ? 0x79AFC53u : 0x442F663u;
    g_Addr_7B0B340 = g_IsSteam ? 0x7B0B340u : 0x45EAE00u;
    g_Addr_7B0C3D0 = g_IsSteam ? 0x7B0C3D0u : 0x45EBA90u;
    g_Addr_8354F40 = g_IsSteam ? 0x8354F40u : 0x8354F40u;
    g_Addr_8FEEF70 = g_IsSteam ? 0x8FEEF70u : 0x152D4D40u;
    g_Addr_91CA540 = g_IsSteam ? 0x91CA540u : 0x15442460u;
    g_Addr_92004C0 = g_IsSteam ? 0x92004C0u : 0x154A6290u;
    g_Addr_98AA180 = g_IsSteam ? 0x98AA180u : 0x98AA180u;
    g_Addr_98AAE20 = g_IsSteam ? 0x98AAE20u : 0x15E001D0u;
    g_Addr_98AAE3B = g_IsSteam ? 0x98AAE3Bu : 0x15E001EBu;
    g_Addr_98AAED1 = g_IsSteam ? 0x98AAED1u : 0x15E00281u;
    g_Addr_98ABC9B = g_IsSteam ? 0x98ABC9Bu : 0x15E0197Bu;
    g_Addr_98ABCE5 = g_IsSteam ? 0x98ABCE5u : 0x15E019C5u;
    g_Addr_98ABD17 = g_IsSteam ? 0x98ABD17u : 0x15E019F7u;
    g_Addr_9F8E980 = g_IsSteam ? 0x9F8E980u : 0x16228E00u;
    g_Addr_9FEC432 = g_IsSteam ? 0x9FEC432u : 0x16257AE2u;
    g_Addr_9FED7B9 = g_IsSteam ? 0x9FED7B9u : 0x1625B3EAu;
    g_Addr_9FED943 = g_IsSteam ? 0x9FED943u : 0x1625B574u;
    g_Addr_A369860 = g_IsSteam ? 0xA369860u : 0x16766D10u;
    g_Addr_A59C196 = g_IsSteam ? 0xA59C196u : 0x16ACCCD6u;
    g_Addr_A6CA200 = g_IsSteam ? 0xA6CA200u : 0xA6CA200u;
    g_Addr_A6BCD30 = g_IsSteam ? 0xA6BCD30u : 0xA6BCD30u;
    g_Addr_10000000 = g_IsSteam ? 0x10000000u : 0x1B2A8000u;
    g_Addr_10C02000 = g_IsSteam ? 0x10C02000u : 0x1B2A8000u;
    g_Addr_10E8544 = g_IsSteam ? 0x10E8544u : 0x10EF594u;
    g_Addr_2C84450 = g_IsSteam ? 0x2C84450u : 0x2C8A840u;
    g_Addr_2C84458 = g_IsSteam ? 0x2C84458u : 0x2C8A848u;
    g_Addr_F8B8B0  = g_IsSteam ? 0xF8B8B0u  : 0x1708EA40u;
    g_Addr_F8BDC0  = g_IsSteam ? 0xF8BDC0u  : 0x17090250u;
    g_Addr_F27DB0  = g_IsSteam ? 0xF27DB0u  : 0x16F77A90u;
    g_Addr_B8F4E0  = g_IsSteam ? 0xB8F4E0u  : 0xB95E90u;
    g_Addr_2CCB738 = g_IsSteam ? 0x2CCB738u : 0x2CD1B98u;
    g_Addr_E862E0  = g_IsSteam ? 0xE862E0u  : 0xE8DFC0u;
    g_Addr_825A60  = g_IsSteam ? 0x825A60u  : 0x82A3C0u;
    g_Addr_EAD660  = g_IsSteam ? 0xEAD660u  : 0xEB52F0u;
    g_Addr_EAE540  = g_IsSteam ? 0xEAE540u  : 0xEB61C0u;
    g_Addr_7B3A50  = g_IsSteam ? 0x7B3A50u  : 0x7B7AF0u;
    g_Addr_7B6D10  = g_IsSteam ? 0x7B6D10u  : 0x7BADC0u;
    g_Addr_B478E0  = g_IsSteam ? 0xB478E0u  : 0xB502A0u;
    g_Addr_A8D8D0  = g_IsSteam ? 0xA8D8D0u  : 0xA93190u;
    g_Addr_27C250  = g_IsSteam ? 0x27C250u  : 0x27D090u;
    g_Addr_2CA54D8 = g_IsSteam ? 0x2CA54D8u : 0x2CAB8B8u;
    g_Addr_17C690  = g_IsSteam ? 0x17C690u  : 0x17C810u;
    g_Addr_286040  = g_IsSteam ? 0x286040u  : 0x286D90u;
    g_Addr_2862F0  = g_IsSteam ? 0x2862F0u  : 0x287040u;
    g_Addr_550930  = g_IsSteam ? 0x550930u  : 0x1482EF10u;
    g_Addr_52CF20  = g_IsSteam ? 0x52CF20u  : 0x146F2230u;
    g_Addr_571AC0  = g_IsSteam ? 0x571AC0u  : 0x5739E0u;
}

namespace { struct RvaPair { uintptr_t s; uintptr_t e; }; }
static const RvaPair kRvaMap[] = {
    {0x78840u, 0x78280u},
    {0x88850u, 0x882F0u},
    {0xF3660u, 0xF3520u},
    {0x11E2C0u, 0x11DC20u},
    {0x1264C0u, 0x1260D0u},
    {0x129570u, 0x129180u},
    {0x12FDD0u, 0x12FA70u},
    {0x1311A0u, 0x130E00u},
    {0x141580u, 0x141200u},
    {0x1B3EDEu, 0x1B469Eu},
    {0x1B7540u, 0x1B7D00u},
    {0x1B7610u, 0x1B7DD0u},
    {0x1B76F0u, 0x1B7EB0u},
    {0x1B7710u, 0x1B7ED0u},
    {0x1B8810u, 0x1B8FE0u},
    {0x1C01B0u, 0x1C0980u},
    {0x1D1640u, 0x1D2060u},
    {0x1D1877u, 0x1D2297u},
    {0x1D1888u, 0x1D22A8u},
    {0x1D189Eu, 0x1D22BEu},
    {0x1D18C5u, 0x1D22E5u},
    {0x20B420u, 0x20BF20u},
    {0x244860u, 0x245360u},
    {0x246470u, 0x4613591u},
    {0x2530B0u, 0x253DE0u},
    {0x253E20u, 0x254B50u},
    {0x286930u, 0x287680u},
    {0x2AC6E0u, 0x486C910u},
    {0x322720u, 0x324070u},
    {0x406CC9u, 0x4085C9u},
    {0x422D60u, 0x424A50u},
    {0x422F0Au, 0x424BFAu},
    {0x422F12u, 0x424C02u},
    {0x423030u, 0x424D20u},
    {0x4230D0u, 0x424DC0u},
    {0x4235BCu, 0x4252ACu},
    {0x4235C5u, 0x4252B5u},
    {0x423655u, 0x425345u},
    {0x424310u, 0x426050u},
    {0x4246E0u, 0x426420u},
    {0x424910u, 0x426650u},
    {0x42AE40u, 0x42CC40u},
    {0x46F2D5u, 0x46DC35u},
    {0x4715D0u, 0x473860u},
    {0x471790u, 0x473A20u},
    {0x471CDAu, 0x473F6Au},
    {0x471EAFu, 0x47413Fu},
    {0x480240u, 0x482680u},
    {0x48F5E0u, 0x491AE0u},
    {0x4936E8u, 0x495C88u},
    {0x49497Du, 0x496F1Du},
    {0x4982BCu, 0x49A8BCu},
    {0x49BA59u, 0x49E0D9u},
    {0x4A6FE1u, 0x4A6C11u},
    {0x4D1F30u, 0x4D3A50u},
    {0x4E2190u, 0x4E3CF0u},
    {0x4E2FC0u, 0x4E4B20u},
    {0x4E6DA0u, 0x4E88A0u},
    {0x4E7340u, 0x4E8E70u},
    {0x4E7980u, 0x4E9490u},
    {0x4E7DD0u, 0x4E98E0u},
    {0x4E7F50u, 0x4E9A60u},
    {0x4E8620u, 0x4EA130u},
    {0x4E9E10u, 0x4EB920u},
    {0x4E9E60u, 0x4EB970u},
    {0x4EA470u, 0x4D4EE0u},
    {0x4EB7A0u, 0x4ED2D0u},
    {0x4EBD30u, 0x4ED870u},
    {0x4F27E5u, 0x4F43C8u},
    {0x4F2C4Au, 0x4F4881u},
    {0x4F2D00u, 0x4F4934u},
    {0x4F5194u, 0x4F7095u},
    {0x4F519Cu, 0x4F709Du},
    {0x531090u, 0x532D90u},
    {0x531160u, 0x532E60u},
    {0x536AC0u, 0x538760u},
    {0x53D7B0u, 0x53F470u},
    {0x53DF40u, 0x53FC00u},
    {0x542110u, 0x543DC0u},
    {0x5509E0u, 0x1482FC81u},
    {0x556D10u, 0x5589A0u},
    {0x556FE0u, 0x558C70u},
    {0x5570D0u, 0x14842F40u},
    {0x5722C0u, 0x5741E0u},
    {0x573520u, 0x575440u},
    {0x574350u, 0x148D2DA1u},
    {0x578F60u, 0x57AE60u},
    {0x594D00u, 0x596C50u},
    {0x6A7630u, 0x6A9E70u},
    {0x6CFBB4u, 0x6D2584u},
    {0x6CFBB9u, 0x6D2589u},
    {0x6F7F40u, 0x6FBAA0u},
    {0x702857u, 0x7063C8u},
    {0x70288Fu, 0x70640Au},
    {0x761BE0u, 0x765B20u},
    {0x761C30u, 0x765B70u},
    {0x761CE0u, 0x765C20u},
    {0x7B3200u, 0x14FC3380u},
    {0x7EAC10u, 0x7EEE90u},
    {0x7F6290u, 0x7FA560u},
    {0x7FE8CCu, 0x802FBCu},
    {0x8F0E40u, 0x8F5CF0u},
    {0x91C920u, 0x921B10u},
    {0x955940u, 0x95AD40u},
    {0x96BBC0u, 0x9710A0u},
    {0xABDFF7u, 0xAC5557u},
    {0xABE007u, 0xAC5567u},
    {0xB1CAF0u, 0xB26020u},
    {0xB28D30u, 0xB31FB0u},
    {0xBADC60u, 0xBB4A80u},
    {0xBB52EFu, 0xBBC16Fu},
    {0xC22480u, 0xC29880u},
    {0xC347B0u, 0xC3B9A0u},
    {0xC37860u, 0xC3EA20u},
    {0xC37EE0u, 0xC3F0A0u},
    {0xC3F540u, 0xC46700u},
    {0xC4C2E0u, 0xC536E0u},
    {0xCB1790u, 0xCB8D30u},
    {0xCE9520u, 0xCF0B80u},
    {0xD74960u, 0xD7C5D0u},
    {0xD74D60u, 0xD7C9D0u},
    {0xD75D70u, 0xD7D9E0u},
    {0xE15C10u, 0xE1D790u},
    {0xEB4D00u, 0xEBC980u},
    {0xFD13A0u, 0xFD7700u},
    {0x1AF9274u, 0x1B017A4u},
    {0x1CAE1C4u, 0x1CB6484u},
    {0x1CAE1CCu, 0x1CB648Cu},
    {0x1CB8220u, 0x1CC0500u},
    {0x1CCB620u, 0x1CD43C0u},
    {0x1D083E0u, 0x1D106C0u},
    {0x1D139E8u, 0x1D1BC90u},
    {0x1D25450u, 0x1D2D418u},
    {0x1D7DF98u, 0x1D85EC8u},
    {0x1D7E0E8u, 0x1D86018u},
    {0x1E01E14u, 0x1E06C44u},
    {0x1E63090u, 0x1E693F0u},
    {0x1E630A0u, 0x1E69400u},
    {0x1E7EEC0u, 0x1E84B78u},
    {0x2AD0F3Cu, 0x2AD7F4Cu},
    {0x2AD0FD0u, 0x2AD7FA0u},
    {0x2AD4324u, 0x2ADB598u},
    {0x2AD4328u, 0x2ADB59Cu},
    {0x2AD432Cu, 0x2ADB5A0u},
    {0x2AD4330u, 0x2ADB5A4u},
    {0x2AD4334u, 0x2ADB5A8u},
    {0x2AD4338u, 0x2ADB5ACu},
    {0x2AD433Cu, 0x2ADB5B0u},
    {0x2AD433Du, 0x2ADB5B1u},
    {0x2AD433Eu, 0x2ADB5B2u},
    {0x2AD433Fu, 0x2ADB5B3u},
    {0x2AD4348u, 0x2ADB5BCu},
    {0x2AD434Cu, 0x2ADB5C0u},
    {0x2AD4350u, 0x2ADB5C4u},
    {0x2AD4354u, 0x2ADB5C8u},
    {0x2AD4358u, 0x2ADB5CCu},
    {0x2AD435Cu, 0x2615AF0u},
    {0x2AD4364u, 0x2ADB2C0u},
    {0x2AD4365u, 0x2ADB2C1u},
    {0x2AD4368u, 0x2ADB2C4u},
    {0x2AD436Cu, 0x2ADB2C8u},
    {0x2AD4370u, 0x2ADB2CCu},
    {0x2AD4374u, 0x2ADB2D0u},
    {0x2AD4378u, 0x2ADB2D4u},
    {0x2AD437Cu, 0x2ADB2D8u},
    {0x2AD4380u, 0x2ADB2DCu},
    {0x2AD4384u, 0x2ADB2E0u},
    {0x2AD4388u, 0x2ADB2E4u},
    {0x2AD438Cu, 0x2ADB2E8u},
    {0x2AD438Du, 0x2ADB2E9u},
    {0x2AD438Eu, 0x2ADB2EAu},
    {0x2AD438Fu, 0x2ADB2EBu},
    {0x2AD4390u, 0x2ADB2ECu},
    {0x2AD4394u, 0x2ADB2F0u},
    {0x2AD4398u, 0x2ADB2F4u},
    {0x2AD439Cu, 0x2ADB2F8u},
    {0x2AD43A0u, 0x2ADB2FCu},
    {0x2AD43A4u, 0x2ADB300u},
    {0x2AD43A8u, 0x2ADB304u},
    {0x2AD43ACu, 0x2ADB308u},
    {0x2AD43B0u, 0x2ADB30Cu},
    {0x2AD43B4u, 0x2ADB310u},
    {0x2AD43B8u, 0x2ADB314u},
    {0x2AD43BCu, 0x2ADB318u},
    {0x2AD43C0u, 0x2ADB31Cu},
    {0x2AD43C4u, 0x2ADB320u},
    {0x2AD43C8u, 0x2ADB324u},
    {0x2AD43CCu, 0x2ADB328u},
    {0x2AD43D0u, 0x2ADB32Cu},
    {0x2AD43D4u, 0x2ADB330u},
    {0x2AD43D8u, 0x2ADB334u},
    {0x2AD43DCu, 0x2ADB338u},
    {0x2AD43E0u, 0x2ADB33Cu},
    {0x2AD43E4u, 0x2ADB340u},
    {0x2AD43F8u, 0x2ADB350u},
    {0x2AD43FCu, 0x2ADB354u},
    {0x2AD4400u, 0x2ADB358u},
    {0x2AD4404u, 0x2ADB35Cu},
    {0x2AD4410u, 0x2ADB368u},
    {0x2AD441Cu, 0x2ADB374u},
    {0x2AD4424u, 0x2ADB37Cu},
    {0x2AD4428u, 0x2ADB380u},
    {0x2AD442Cu, 0x2ADB384u},
    {0x2AD4430u, 0x2ADB388u},
    {0x2AD4434u, 0x2ADB38Cu},
    {0x2AD4438u, 0x2ADB390u},
    {0x2AD4440u, 0x2ADB398u},
    {0x2AD4444u, 0x2ADB39Cu},
    {0x2AD444Cu, 0x2ADB3A4u},
    {0x2AD4450u, 0x2ADB3A8u},
    {0x2AD4454u, 0x2ADB3ACu},
    {0x2AD4458u, 0x2ADB3B0u},
    {0x2AD445Cu, 0x2ADB3B4u},
    {0x2AD4460u, 0x2ADB3B8u},
    {0x2AD4470u, 0x2ADB3C8u},
    {0x2AD4474u, 0x2ADB3CCu},
    {0x2AD4484u, 0x2ADB3DCu},
    {0x2AD4488u, 0x2ADB3E0u},
    {0x2AD448Cu, 0x2ADB3E4u},
    {0x2AD4490u, 0x2ADB3E8u},
    {0x2AD4491u, 0x2ADB3E9u},
    {0x2AD4492u, 0x2ADB3EAu},
    {0x2AD449Cu, 0x2ADB3F4u},
    {0x2AD449Du, 0x2ADB3F5u},
    {0x2AD44A4u, 0x2ADB3FCu},
    {0x2AD44A8u, 0x2ADB400u},
    {0x2AD44ACu, 0x2ADB404u},
    {0x2AD44B0u, 0x2ADB408u},
    {0x2AD44B4u, 0x2ADB40Cu},
    {0x2AD44B8u, 0x2ADB410u},
    {0x2AD44C0u, 0x2ADB418u},
    {0x2AD44F0u, 0x2ADB448u},
    {0x2AD44F4u, 0x2ADB44Cu},
    {0x2AD44F8u, 0x2ADB450u},
    {0x2AD44FCu, 0x2ADB454u},
    {0x2AD4500u, 0x2ADB458u},
    {0x2AD4501u, 0x2ADB459u},
    {0x2AD4502u, 0x2ADB45Au},
    {0x2AD4503u, 0x2ADB45Bu},
    {0x2AD4504u, 0x2ADB45Cu},
    {0x2AD4505u, 0x2ADB45Du},
    {0x2AD4506u, 0x2ADB45Eu},
    {0x2AD4507u, 0x2ADB45Fu},
    {0x2AD4508u, 0x2ADB460u},
    {0x2AD4509u, 0x2ADB461u},
    {0x2AD450Au, 0x2ADB462u},
    {0x2AD450Bu, 0x2ADB463u},
    {0x2AD450Cu, 0x2ADB464u},
    {0x2AD450Du, 0x2ADB465u},
    {0x2AD450Eu, 0x2ADB466u},
    {0x2AD450Fu, 0x2ADB467u},
    {0x2AD4510u, 0x2ADB468u},
    {0x2AD4511u, 0x2ADB469u},
    {0x2AD4512u, 0x2ADB46Au},
    {0x2AD4513u, 0x2ADB46Bu},
    {0x2AD4514u, 0x2ADB46Cu},
    {0x2AD4515u, 0x2ADB46Du},
    {0x2AD4516u, 0x2ADB46Eu},
    {0x2AD4517u, 0x2ADB46Fu},
    {0x2AD451Cu, 0x2ADB474u},
    {0x2AD457Cu, 0x2ADB4D4u},
    {0x2AD4580u, 0x2ADB4D8u},
    {0x2AD4584u, 0x2ADB4DCu},
    {0x2AD458Cu, 0x2ADB4E4u},
    {0x2AD4590u, 0x2ADB4E8u},
    {0x2AD4594u, 0x2ADB4ECu},
    {0x2AD4598u, 0x2ADB4F0u},
    {0x2AD459Cu, 0x2ADB4F4u},
    {0x2AD45A4u, 0x2ADB4FCu},
    {0x2AD45A8u, 0x2ADB500u},
    {0x2AD45B8u, 0x2ADB510u},
    {0x2AD45BCu, 0x2ADB514u},
    {0x2AD45C0u, 0x2ADB518u},
    {0x2AD6850u, 0x2ADD860u},
    {0x2AE2760u, 0x2AE9260u},
    {0x2AE55F0u, 0x2AEC04Cu},
    {0x2AE55F8u, 0x2AEC054u},
    {0x2AE55F9u, 0x2AEC055u},
    {0x2AE5610u, 0x2AEC06Cu},
    {0x2AE9720u, 0x2AF0138u},
    {0x2AE9724u, 0x2AF013Cu},
    {0x2AE9728u, 0x2AF0140u},
    {0x2AE972Cu, 0x2AF0144u},
    {0x2AE9730u, 0x2AF0148u},
    {0x2AE9768u, 0x2AF0180u},
    {0x2AE976Cu, 0x2AF0184u},
    {0x2AE9770u, 0x2AF0188u},
    {0x2AE9774u, 0x2AF018Cu},
    {0x2AE9778u, 0x2AF0190u},
    {0x2AE9780u, 0x2AF0198u},
    {0x2AE9784u, 0x2AF019Cu},
    {0x2AEAD0Cu, 0x2AF1774u},
    {0x2AEAD10u, 0x2AF1778u},
    {0x2AF1E64u, 0x2AF88C4u},
    {0x2AF1E68u, 0x2AF88C8u},
    {0x2C73AE0u, 0x2C79ED0u},
    {0x2C84450u, 0x2C8A840u},
    {0x2C846B0u, 0x2C8AAA8u},
    {0x2CA5880u, 0x2CABC68u},
    {0x2CADA68u, 0x2CB3E48u},
    {0x2CAF970u, 0x2CB5D30u},
    {0x2CAFA50u, 0x2CB5E10u},
    {0x2CAFDB0u, 0x2CB6170u},
    {0x2CB0A48u, 0x2CB6E08u},
    {0x2CB1938u, 0x2CB7D08u},
    {0x2CB1D20u, 0x2CB80F0u},
    {0x2CB1D38u, 0x2CB8108u},
    {0x2CB1D90u, 0x2CB8160u},
    {0x2CB1D98u, 0x2CB8168u},
    {0x2CB2388u, 0x2CB8758u},
    {0x2CB4B28u, 0x2CBAEF8u},
    {0x2CB4B30u, 0x2CBAF00u},
    {0x2CB5C70u, 0x2CBC040u},
    {0x2CB5ED0u, 0x2CBC2A0u},
    {0x2CB9CB0u, 0x2CC1270u},
    {0x2CBD1B0u, 0x2CC37D8u},
    {0x2CE3F30u, 0x2CEA370u},
    {0x6000000u, 0x1B2A8000u},
    {0x75C5E60u, 0x3EF7EE1u},
    {0x7600060u, 0x3F48110u},
    {0x76014E0u, 0x3F4A670u},
    {0x77B4BFBu, 0x419BB8Bu},
    {0x77BCA70u, 0x41A4AD0u},
    {0x77BCBDDu, 0x41A4C3Du},
    {0x77BDE85u, 0x41A5ED0u},
    {0x77BE2FEu, 0x41A6351u},
    {0x77BE4A6u, 0x41A64FCu},
    {0x77BE5A5u, 0x41A6602u},
    {0x77BE81Du, 0x41A686Bu},
    {0x79AFC53u, 0x442F663u},
    {0x7B0B340u, 0x45EAE00u},
    {0x7B0C3D0u, 0x45EBA90u},
    {0x81DAD9Eu, 0x1451B7BEu},
    {0x81DADA6u, 0x1451B7C6u},
    {0x81E1519u, 0x14525249u},
    {0x81E1559u, 0x14525289u},
    {0x824A840u, 0x145B1280u},
    {0x8FEEF70u, 0x152D4D40u},
    {0x91CA540u, 0x15442460u},
    {0x92004C0u, 0x154A6290u},
    {0x98AAE20u, 0x15E001D0u},
    {0x98AAE3Bu, 0x15E001EBu},
    {0x98AAED1u, 0x15E00281u},
    {0x98ABC9Bu, 0x15E0197Bu},
    {0x98ABCE5u, 0x15E019C5u},
    {0x98ABD17u, 0x15E019F7u},
    {0x9964A4Cu, 0x15ED9DCCu},
    {0x9F8E980u, 0x16228E00u},
    {0x9FEC432u, 0x16257AE2u},
    {0x9FED7B9u, 0x1625B3EAu},
    {0x9FED943u, 0x1625B574u},
    {0xA369860u, 0x16766D10u},
    {0xA59C196u, 0x16ACCCD6u},
    {0x10E8544u, 0x10EF594u},
    {0x10000000u, 0x1B2A8000u},
    {0x10C02000u, 0x1B2A8000u},
};
static const unsigned kRvaMapN = sizeof(kRvaMap)/sizeof(kRvaMap[0]);
uintptr_t JRVA(uintptr_t steam_rva) {
    if (g_IsSteam || !steam_rva) return steam_rva;
    unsigned lo = 0, hi = kRvaMapN;
    while (lo < hi) { unsigned mid = (lo + hi) >> 1;
        if (kRvaMap[mid].s <= steam_rva) lo = mid + 1; else hi = mid; }
    if (lo > 0 && kRvaMap[lo-1].s == steam_rva) return kRvaMap[lo-1].e;
    return steam_rva;
}
bool JRVA_KNOWN(uintptr_t steam_rva) {
    if (g_IsSteam) return true;
    if (!steam_rva) return false;
    unsigned lo = 0, hi = kRvaMapN;
    while (lo < hi) { unsigned mid = (lo + hi) >> 1;
        if (kRvaMap[mid].s <= steam_rva) lo = mid + 1; else hi = mid; }
    return (lo > 0 && kRvaMap[lo-1].s == steam_rva);
}
