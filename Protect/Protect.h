// ���� ifdef ���Ǵ���ʹ�� DLL �������򵥵�
// ��ı�׼�������� DLL �е������ļ��������������϶���� PROTECT_EXPORTS
// ���ű���ġ���ʹ�ô� DLL ��
// �κ�������Ŀ�ϲ�Ӧ����˷��š�������Դ�ļ��а������ļ����κ�������Ŀ���Ὣ
// PROTECT_API ������Ϊ�Ǵ� DLL ����ģ����� DLL ���ô˺궨���
// ������Ϊ�Ǳ������ġ�
#ifdef PROTECT_EXPORTS
#define PROTECT_API __declspec(dllexport)
#else
#define PROTECT_API __declspec(dllimport)
#endif

// �����Ǵ� Protect.dll ������
class PROTECT_API CProtect {
public:
	CProtect(void);
	// TODO: �ڴ�������ķ�����
};

extern PROTECT_API int nProtect;

PROTECT_API int fnProtect(void);
