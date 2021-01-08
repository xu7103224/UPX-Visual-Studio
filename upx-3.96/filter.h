/* filter.h --

   This file is part of the UPX executable compressor.

   Copyright (C) 1996-2020 Markus Franz Xaver Johannes Oberhumer
   Copyright (C) 1996-2020 Laszlo Molnar
   All Rights Reserved.

   UPX and the UCL library are free software; you can redistribute them
   and/or modify them under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of
   the License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; see the file COPYING.
   If not, write to the Free Software Foundation, Inc.,
   59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

   Markus F.X.J. Oberhumer              Laszlo Molnar
   <markus@oberhumer.com>               <ezerotven+github@gmail.com>
 */


#ifndef __UPX_FILTER_H
#define __UPX_FILTER_H 1

class Filter;
class FilterImp;


/*************************************************************************
// A filter is a reversible operation that modifies a given
// block of memory.
//
// A filter can fail and return false. In this case the buffer
// must be unmodified (or otherwise restored).
//
// If a filter fails and somehow cannot restore the block it must
// call throwFilterException() - this will cause the compression
// to fail.
//
// Unfilters throw exceptions in case of errors.
//
// The main idea behind filters is to convert relative jumps and calls
// to absolute addresses so that the buffer compresses better.
**************************************************************************/

/*
* ��������һ�ֿ�����������޸ĸ������ڴ�顣
* ɸѡ�����ܻ�ʧ�ܲ�����false������������£�������벻���޸ģ�����������ʽ��ԭ����
* ���һ��������ʧ�ܲ����޷��ָ��飬���������throwFilterException���������⽫����ѹ��ʧ�ܡ�
* ������ִ����׳�δѹ���쳣��
* ����������뷨�ı�����ͨ��ת�������ת�͵��õ�ַΪ���Ե�ַ���������Ը��õؽ�����ѹ����
*/
class Filter
{
public:
    Filter(int level) { clevel = level; init(); }
    void init(int id=0, unsigned addvalue=0);

    bool filter(upx_byte *buf, unsigned buf_len);
    void unfilter(upx_byte *buf, unsigned buf_len, bool verify_checksum=false);
    void verifyUnfilter();
    bool scan(const upx_byte *buf, unsigned buf_len);

    static bool isValidFilter(int filter_id);
    static bool isValidFilter(int filter_id, const int *allowed_filters);

public:
    // Will be set by each call to filter()/unfilter().
    // Read-only afterwards.
    // ����ÿ�ε���filter���� / unfilter�������á��Ժ�ֻ����
    upx_byte *buf; // �������˵Ļ���
    unsigned buf_len; // �����С

    // Checksum of the buffer before applying the filter
    // or after un-applying the filter.
    // ����ɸѡ��������ɾѡ��֮��Ļ�����У��ֵ
    unsigned adler; // ����ԭʼ�����У��ֵ��ʹ�� upx_adler32����У�顣

    // Input parameters used by various filters.
    // ���ֹ�����ʹ�õ����������
    unsigned addvalue;
    const int *preferred_ctos;

    // Input/output parameters used by various filters
    // ��ת��Χ���ڴ���鷶Χ��ƫ�����ֽڵ����±���buf�б��λ1�������¼���Ǵ�buf���ֽڿ�ʼ��һ����Ϊ1���ֽ��±�
    unsigned char cto;   // call trick offset

    // Output used by various filters. Read only.
    unsigned calls; // �ۼƵ���ָ����
    unsigned noncalls; // �ǵ��õ�E8����E9����
    unsigned wrongcalls;
    unsigned firstcall;
    unsigned lastcall; // ָ����һ������ָ��ĺ�һ��ָ��
    unsigned n_mru;  // ctojr only

    // Read only.
    int id;

private:
    int clevel;         // compression level
};


/*************************************************************************
// We don't want a full OO interface here because of
// certain implementation speed reasons.
//
// This class is private to Filter - don't look.
**************************************************************************/

//�������Ĺ�����
class FilterImp
{
    friend class Filter;

private:
    struct FilterEntry
    {
        int id;                             // id ��Χ 0 ~ 255
        unsigned min_buf_len;
        unsigned max_buf_len;
        // filter a buffer
        int (*do_filter)(Filter *);         // ɸѡһ�黺��
        // unfilter a buffer
        int (*do_unfilter)(Filter *);       // ��ԭһ�黺��
        // scan a buffer
        int (*do_scan)(Filter *);           // ɨ��һ�黺��
    };

    // get a specific filter entry
    // ��ȡһ��ָ��������
    static const FilterEntry *getFilter(int id);

private:
    // strictly private filter database
    // �ϸ�˽�еĹ��������ݿ�
    static const FilterEntry filters[];
    // number of filters[]
    // ���������������
    static const int n_filters;             
};


#endif /* already included */

/* vim:set ts=4 sw=4 et: */
