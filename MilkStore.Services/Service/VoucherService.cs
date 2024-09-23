using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using MilkStore.Contract.Repositories.Entity;
using MilkStore.Contract.Repositories.Interface;
using MilkStore.Contract.Services.Interface;
using MilkStore.Core.Base;
using MilkStore.Core.Constants;
using MilkStore.Core.Utils;
using MilkStore.ModelViews.AuthModelViews;
using MilkStore.ModelViews.VoucherModelViews;
using MilkStore.ModelViews.UserModelViews;
using MilkStore.Repositories.Context;
using MilkStore.Repositories.Entity;
using static System.Runtime.InteropServices.JavaScript.JSType;
using AutoMapper;
using MilkStore.Core;

namespace MilkStore.Services.Service
{
    public class VoucherService : IVoucherService
    {
        private readonly IUnitOfWork _unitOfWork;
        private readonly DatabaseContext context;
        private readonly IMapper _mapper;

        public VoucherService(DatabaseContext context, IUnitOfWork unitOfWork, IMapper mapper)
        {
            this.context = context;
            _unitOfWork = unitOfWork;
            _mapper = mapper;
        }

        public async Task<Voucher> CreateVoucher(VoucherModelView voucherModel)
        {
            Voucher newVoucher = _mapper.Map<Voucher>(voucherModel);
            newVoucher.CreatedTime = CoreHelper.SystemTimeNow;
            newVoucher.LastUpdatedTime = CoreHelper.SystemTimeNow;
            newVoucher.DeletedTime = null;

            await _unitOfWork.GetRepository<Voucher>().InsertAsync(newVoucher);
            await _unitOfWork.SaveAsync();
            return newVoucher;
        }

        public async Task DeleteVoucher(string id)
        {
            Voucher voucher = await _unitOfWork.GetRepository<Voucher>().GetByIdAsync(id);
            if (voucher == null)
            {
                throw new KeyNotFoundException($"Voucher with ID: {id} was not found.");
            }
            voucher.DeletedTime = CoreHelper.SystemTimeNow;

            await _unitOfWork.GetRepository<Voucher>().UpdateAsync(voucher);
            await _unitOfWork.SaveAsync();
        }

        public async Task<BasePaginatedList<Voucher>> GetVouchers(string? name, int pageIndex, int pageSize)
        {
            var query = _unitOfWork.GetRepository<Voucher>().Entities
                .Where(voucher => voucher.DeletedTime == null);

            if (!string.IsNullOrWhiteSpace(name))
            {
                query = query.Where(voucher => voucher.Name.Contains(name));
            }

            var totalItems = await query.CountAsync();

            var vouchers = await query
                .OrderByDescending(voucher => voucher.CreatedTime)
                .Skip(pageIndex * pageSize)
                .Take(pageSize)
                .ToListAsync();

            return new BasePaginatedList<Voucher>(
                vouchers,
                totalItems,
                pageIndex,
                pageSize
            );
        }


        public async Task<Voucher> UpdateVoucher(string id, VoucherModelView voucherModel)
        {
            Voucher voucher = await _unitOfWork.GetRepository<Voucher>().GetByIdAsync(id);
            if (voucher == null)
            {
                throw new KeyNotFoundException($"Voucher with ID: {id} was not found.");
            }

            _mapper.Map(voucherModel, voucher); // Ánh xạ giá trị mới từ voucherModel vào voucher hiện có
            voucher.LastUpdatedTime = CoreHelper.SystemTimeNow;

            await _unitOfWork.GetRepository<Voucher>().UpdateAsync(voucher);
            await _unitOfWork.SaveAsync();
            return voucher;
        }
    }
}
