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
* 过滤器是一种可逆操作，它修改给定的内存块。
* 筛选器可能会失败并返回false。在这种情况下，缓存必须不被修改（或以其他方式还原）。
* 如果一个过滤器失败并且无法恢复块，它必须调用throwFilterException（）——这将导致压缩失败。
* 如果出现错误，抛出未压缩异常。
* 这个过滤器想法的背后是通过转换相对跳转和调用地址为绝对地址，这样可以更好地将缓存压缩。
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
    // 将由每次调用filter（） / unfilter（）设置。以后只读。
    upx_byte *buf; // 将被过滤的缓存
    unsigned buf_len; // 缓存大小

    // Checksum of the buffer before applying the filter
    // or after un-applying the filter.
    // 启用筛选器和弃用删选器之后的缓冲区校验值
    unsigned adler; // 就是原始缓存的校验值，使用 upx_adler32函数校验。

    // Input parameters used by various filters.
    // 各种过滤器使用的输入参数。
    unsigned addvalue;
    const int *preferred_ctos;

    // Input/output parameters used by various filters
    // 跳转范围大于代码块范围则将偏移首字节当成下表在buf中标记位1，这里记录的是从buf首字节开始第一个不为1的字节下标
    unsigned char cto;   // call trick offset

    // Output used by various filters. Read only.
    unsigned calls; // 累计调用指令数
    unsigned noncalls; // 非调用的E8或者E9数量
    unsigned wrongcalls;
    unsigned firstcall;
    unsigned lastcall; // 指向上一个调用指令的后一条指令
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

//过滤器的管理类
class FilterImp
{
    friend class Filter;

private:
    struct FilterEntry
    {
        int id;                             // id 范围 0 ~ 255
        unsigned min_buf_len;
        unsigned max_buf_len;
        // filter a buffer
        int (*do_filter)(Filter *);         // 筛选一块缓存
        // unfilter a buffer
        int (*do_unfilter)(Filter *);       // 还原一块缓存
        // scan a buffer
        int (*do_scan)(Filter *);           // 扫描一块缓存
    };

    // get a specific filter entry
    // 获取一个指定过滤器
    static const FilterEntry *getFilter(int id);

private:
    // strictly private filter database
    // 严格私有的过滤数器据库
    static const FilterEntry filters[];
    // number of filters[]
    // 过滤器数组的数量
    static const int n_filters;             
};


#endif /* already included */

/* vim:set ts=4 sw=4 et: */
