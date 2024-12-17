#include <stdio.h>
#include <pcap.h>
#include <time.h>

/*
    #prgma comment(lib, ..)
    �ܺ� ���̺귯���� ��������� ������ �ʿ� ���� �����Ϸ��� �ڵ����� ���̺귯���� �����Ű�� ���þ��̴�.
*/
#pragma comment(lib, "wpcap")  // Npcap or WinPacap ���̺귯�� ��ũ
#pragma comment(lib, "ws2_32") // Windows Sockets2 ���̺귯�� ��ũ

#include <tchar.h>
#include <WinSock2.h>


/*
    �⺻������ C�����Ϸ��� ������ Ÿ�Կ� �°� �޸������� ����ȭ�Ѵ�.
    #pragma pack(push,1)�� �̸� �����ϰ� �� ��� �������� 1����Ʈ ������ �޸� �� ��ġ�ϵ��� �Ѵ�.
    ��, �Ʒ� ����ü�� dstMac[6]=6Byte, srcMac[6]=6Byte, type
*/
#pragma pack(push, 1)  // ����ü �޸� ������ 1����Ʈ�� ����
typedef struct EtherHeader {
    unsigned char dstMac[6];  // ������ MAC �ּ�
    unsigned char srcMac[6];  // ����� MAC �ּ�
    unsigned short type;      // �̴��� Ÿ�� (��: IP, ARP ��)
} EtherHeader;
#pragma pack(pop)  // ����ü �޸� ������ ������� ����

// Npcap DLL�� �ε��ϴ� �Լ�
BOOL LoadNpcapDlls()
{
    _TCHAR npcap_dir[512];  // Npcap�� ��ġ�� ���丮 ��θ� ������ �迭
    UINT len;
    len = GetSystemDirectory(npcap_dir, 480);  // �ý��� ���丮 ��� ��������
    if (!len) {
        fprintf(stderr, "GetSystemDirectory���� ���� �߻�: %x", GetLastError());
        return FALSE;  // ���� �߻� �� FALSE ��ȯ
    }
    _tcscat_s(npcap_dir, 512, _T("\\Npcap"));  // Npcap ��� �߰�
    if (SetDllDirectory(npcap_dir) == 0) {  // DLL ���丮 ����
        fprintf(stderr, "SetDllDirectory���� ���� �߻�: %x", GetLastError());
        return FALSE;  // ���� �߻� �� FALSE ��ȯ
    }

    return TRUE;  // ���������� Npcap�� �ε��� ��� TRUE ��ȯ
}

// ��Ŷ ���� �� ó���ϴ� �ݹ� �Լ�
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
    struct tm ltime;  // ���� �ð� ����ü
    char timestr[16];  // �ð��� ������ ���ڿ�
    time_t local_tv_sec;  // ��Ŷ�� timestamp�� ������ ����

    /* timestamp�� ����� ���� �� �ִ� �������� ��ȯ */
    local_tv_sec = header->ts.tv_sec;  // ��Ŷ ���� �ð��� �� ������ ������
    localtime_s(&ltime, &local_tv_sec);  // �� ������ ���� �ð����� ��ȯ
    strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);  // �ð� ���ڿ� ���� ����

    EtherHeader* pEther = (EtherHeader*)pkt_data;  // ��Ŷ �����͸� EtherHeader ����ü�� ��ȯ

    // ��Ŷ ���� ���: �ð�, ����, MAC �ּ�, �̴��� Ÿ��
    printf("%s,%.6d len:%d, "
        "SRC: %02X-%02X-%02X-%02X-%02X-%02X -> "
        "DST: %02X-%02X-%02X-%02X-%02X-%02X, type:%04X\n",
        timestr, header->ts.tv_usec, header->len,
        pEther->srcMac[0], pEther->srcMac[1], pEther->srcMac[2],
        pEther->srcMac[3], pEther->srcMac[4], pEther->srcMac[5],
        pEther->dstMac[0], pEther->dstMac[1], pEther->dstMac[2],
        pEther->dstMac[3], pEther->dstMac[4], pEther->dstMac[5],
        ntohs(pEther->type));  // �̴��� Ÿ���� ��Ʈ��ũ ����Ʈ �������� ȣ��Ʈ ����Ʈ ������ ��ȯ
}

int main()
{
    pcap_if_t* alldevs;  // ��Ʈ��ũ ��ġ ���
    pcap_if_t* d;        // ���� ��Ʈ��ũ ��ġ
    int inum;            // ������ ��ġ ��ȣ
    int i = 0;
    pcap_t* adhandle;    // ��Ŷ ĸó �ڵ�
    char errbuf[PCAP_ERRBUF_SIZE];  // ���� ����

    // Npcap DLL �ε�
    if (!LoadNpcapDlls())
    {
        fprintf(stderr, "Npcap�� �ε��� �� �����ϴ�.\n");
        exit(1);
    }

    // ��Ʈ��ũ ��ġ ����� ��������
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr, "pcap_findalldevs���� ���� �߻�: %s\n", errbuf);
        exit(1);
    }

    // ��Ʈ��ũ ��ġ ��� ���
    for (d = alldevs; d; d = d->next)
    {
        printf("%d. %s", ++i, d->name);  // ��ġ ��ȣ�� �̸� ���
        if (d->description)
            printf(" (%s)\n", d->description);  // ��ġ ���� ���
        else
            printf(" (���� ����)\n");  // ������ ���� ���
    }

    if (i == 0)  // ��ġ�� �ϳ��� ������ ���� �޽��� ���
    {
        printf("\n�������̽��� �����ϴ�! Npcap�� ��ġ�Ǿ� �ִ��� Ȯ���ϼ���.\n");
        return -1;
    }

    // ����ڿ��� ��ġ ���� ��û
    printf("�������̽� ��ȣ�� �Է��ϼ��� (1-%d):", i);
    scanf_s("%d", &inum);  // ����ڷκ��� �������̽� ��ȣ �Է�

    if (inum < 1 || inum > i)  // ��ȿ���� ���� ��ȣ �Է� �� ���� �޽��� ���
    {
        printf("\n�������̽� ��ȣ�� ������ ������ϴ�.\n");
        pcap_freealldevs(alldevs);  // ��ġ ��� ����
        return -1;
    }

    // ������ ��ġ�� �̵�
    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

    // ��ġ ����
    if ((adhandle = pcap_open_live(d->name,  // ��ġ �̸�
        65536,          // ĸó�� ��Ŷ ũ�� (��ü ��Ŷ ĸó)
        1,              // ���ι̽�ť� ��� (1�̸� ���ι̽�ť� ��� Ȱ��ȭ)
        1000,           // Ÿ�Ӿƿ� (�и��� ����)
        errbuf          // ���� ����
    )) == NULL)
    {
        fprintf(stderr, "\n����͸� �� �� �����ϴ�. %s�� Npcap���� �������� �ʽ��ϴ�.\n", d->name);
        pcap_freealldevs(alldevs);  // ��ġ ��� ����
        return -1;
    }

    printf("\n%s���� ��Ŷ�� ���� ��...\n", d->description);  // ��Ŷ ĸó ���� �޽��� ���

    pcap_freealldevs(alldevs);  // ��ġ ����� �� �̻� �ʿ� �����Ƿ� ����

    // ��Ŷ ĸó ����
    pcap_loop(adhandle, 0, packet_handler, NULL);  // ��Ŷ�� ������ ������ packet_handler ȣ��

    pcap_close(adhandle);  // ��Ŷ ĸó �ڵ� �ݱ�

    return 0;
}
