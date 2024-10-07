using AutoMapper;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using MilkStore.Contract.Repositories.Entity;
using MilkStore.Contract.Repositories.Interface;
using MilkStore.Contract.Services.Interface;
using MilkStore.Core;
using MilkStore.Core.Base;
using MilkStore.Core.Constants;
using MilkStore.Core.Utils;
using MilkStore.ModelViews.VoucherModelViews;
using MilkStore.ModelViews.ResponseDTO;

namespace MilkStore.Services.Service
{
    public class VoucherService : IVoucherService
    {
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMapper _mapper;

        public VoucherService(IUnitOfWork unitOfWork, IMapper mapper)
        {
            _unitOfWork = unitOfWork;
            _mapper = mapper;
        }

        public async Task CreateVoucher(VoucherModelView voucherModel)
        {
            Voucher newVoucher = _mapper.Map<Voucher>(voucherModel);
            newVoucher.CreatedTime = CoreHelper.SystemTimeNow;
            newVoucher.LastUpdatedTime = CoreHelper.SystemTimeNow;
            newVoucher.DeletedTime = null;

            await _unitOfWork.GetRepository<Voucher>().InsertAsync(newVoucher);
            await _unitOfWork.SaveAsync();
        }

        public async Task DeleteVoucher(string id)
        {
            if (string.IsNullOrWhiteSpace(id))
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Please enter voucher ID!");
            }

            Voucher? voucher = await _unitOfWork.GetRepository<Voucher>().GetByIdAsync(id)
                ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, $"No voucher found with ID {id}");

            if (voucher.DeletedTime != null)
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, "This voucher has already been deleted!");
            }

            voucher.DeletedTime = CoreHelper.SystemTimeNow;
            await _unitOfWork.GetRepository<Voucher>().UpdateAsync(voucher);
            await _unitOfWork.SaveAsync();
        }

        public async Task<BasePaginatedList<VoucherResponseDTO>> GetVouchers(string? name, int pageIndex, int pageSize)
        {
            IQueryable<Voucher>? query = _unitOfWork.GetRepository<Voucher>().Entities.Where(voucher => voucher.DeletedTime == null);

            if (!string.IsNullOrWhiteSpace(name))
            {
                query = query.Where(voucher => voucher.Name.Contains(name));
            }

            BasePaginatedList<Voucher>? paginatedVouchers = await _unitOfWork.GetRepository<Voucher>().GetPagging(query, pageIndex, pageSize);

            if (!paginatedVouchers.Items.Any() && !string.IsNullOrWhiteSpace(name))
            {
                List<Voucher>? vouchersByName = await _unitOfWork.GetRepository<Voucher>().Entities
                    .Where(voucher => voucher.Name.Contains(name) && voucher.DeletedTime == null)
                    .ToListAsync();

                if (vouchersByName.Any())
                {
                    List<VoucherResponseDTO>? voucherDtosByName = _mapper.Map<List<VoucherResponseDTO>>(vouchersByName);
                    return new BasePaginatedList<VoucherResponseDTO>(voucherDtosByName, vouchersByName.Count, 1, pageSize);
                }
            }

            List<VoucherResponseDTO>? voucherDtosResult = _mapper.Map<List<VoucherResponseDTO>>(paginatedVouchers.Items);
            return new BasePaginatedList<VoucherResponseDTO>(
                voucherDtosResult,
                paginatedVouchers.TotalItems,
                paginatedVouchers.CurrentPage,
                paginatedVouchers.PageSize
            );
        }

        public async Task UpdateVoucher(string id, VoucherModelView voucherModel)
        {
            if (string.IsNullOrWhiteSpace(id))
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Please enter voucher ID!");
            }

            Voucher? voucher = await _unitOfWork.GetRepository<Voucher>().GetByIdAsync(id)
                ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, $"No voucher found with ID {id}");

            _mapper.Map(voucherModel, voucher);

            voucher.LastUpdatedTime = CoreHelper.SystemTimeNow;

            await _unitOfWork.GetRepository<Voucher>().UpdateAsync(voucher);
            await _unitOfWork.SaveAsync();
        }
    }
}
