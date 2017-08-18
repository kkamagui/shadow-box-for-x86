/*
 *                          Shadow-Box
 *                         ------------
 *      Lightweight Hypervisor-Based Kernel Protector
 *
 *               Copyright (C) 2017 Seunghun Han
 *     at National Security Research Institute of South Korea
 */

/*
 * This software has dual license (MIT and GPL v2). See the GPL_LICENSE and
 * MIT_LICENSE file.
 */
#ifndef __IOMMU_H__
#define __IOMMU_H__

/*
 * Macros.
 */
/* Page table flags. */
#define PS_BIT						(0x01 << 7)
#define ENTRY_PRESENT				(0x01 << 0)
#define ENTRY_FAULT_PROC_DISABLE	(0x01 << 1)
#define ENTRY_3LEVEL_PTE			(0x01 << 0)
#define ENTRY_4LEVEL_PTE			(0x01 << 1)

#define IOMMU_PAGE_PRESENT			(0x01 << 0)
#define IOMMU_PAGE_RW				(0x01 << 1)
#define IOMMU_PAGE_ALL_ACCESS		(IOMMU_PAGE_PRESENT | IOMMU_PAGE_RW)

/* Page size macro. */
#define VAL_256TB         			((u64)256 * 1024 * 1024 * 1024 * 1024)
#define VAL_512GB					((u64)512 * 1024 * 1024 * 1024)
#define VAL_1GB						((u64)1024 * 1024 * 1024)
#define VAL_2MB						((u64)2 * 1024 * 1024)
#define VAL_4KB						((u64)4 * 1024)
#define CEIL(X, Y) 					(((X) + (Y) - 1) / (Y))
#define IOMMU_PAGE_ENT_COUNT		512
#define IOMMU_PAGE_SIZE				4096

/* DMAR page type. */
#define IOMMU_TYPE_PML4				0
#define IOMMU_TYPE_PDPTEPD			1
#define IOMMU_TYPE_PDEPT			2
#define IOMMU_TYPE_PTE				3

/*
 * Structures.
 */
struct sb_iommu_pagetable
{
	u64 entry[512];
};

/* IOMMU information structure. */
struct sb_iommu_info
{
	u64 pml4_ent_count;
	u64 pdpte_pd_ent_count;
	u64 pdept_ent_count;
	u64 pte_ent_count;
	u64 pml4_page_count;
	u64 pdpte_pd_page_count;
	u64 pdept_page_count;
	u64 pte_page_count;
	u64* pml4_page_addr_array;
	u64* pdpte_pd_page_addr_array;
	u64* pdept_page_addr_array;
	u64* pte_page_addr_array;

	u64* root_entry_table_addr;
	u64* context_entry_table_addr;
};

/* Root table entry structure. */
struct root_entry
{
	u64	val;
	u64	rsvd1;
};

/* Context table entry structure. */
struct context_entry
{
	u64	lo;
	u64	hi;
};

/*
 * Functions.
 */
void sb_lock_iommu(void);
void sb_unlock_iommu(void);
int sb_alloc_iommu_pages(void);
void sb_free_iommu_pages(void);
void sb_protect_iommu_pages(void);
void sb_set_iommu_page_flags(u64 phy_addr, u32 flags);
void sb_set_iommu_hide_page(u64 phy_addr);
void sb_set_iommu_all_access_page(u64 phy_addr);
void sb_setup_iommu_pagetable_4KB(void);
int sb_check_iommu(void);

#endif
