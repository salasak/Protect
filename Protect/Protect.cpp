// Protect.cpp : ���� DLL Ӧ�ó���ĵ���������
//

#include "stdafx.h"
#include "Protect.h"


// ���ǵ���������һ��ʾ��
PROTECT_API int nProtect=0;

// ���ǵ���������һ��ʾ����
PROTECT_API int fnProtect(void)
{
	return 42;
}

// �����ѵ�����Ĺ��캯����
// �й��ඨ�����Ϣ������� Protect.h
CProtect::CProtect()
{
	return;
}
