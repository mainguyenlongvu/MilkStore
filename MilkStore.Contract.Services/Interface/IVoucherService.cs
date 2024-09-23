using Microsoft.AspNetCore.Identity;
using MilkStore.Contract.Repositories.Entity;
using MilkStore.Core;
using MilkStore.ModelViews.VoucherModelViews;
using MilkStore.Repositories.Entity;

namespace MilkStore.Contract.Services.Interface
{
    public interface IVoucherService
    {
        Task<BasePaginatedList<Voucher>> GetVouchers(string? name, int pageIndex, int pageSize);
        Task<Voucher> CreateVoucher(VoucherModelView voucherModel);
        Task<Voucher> UpdateVoucher(string id, VoucherModelView voucherModel);
        Task DeleteVoucher(string id);
    }
}
