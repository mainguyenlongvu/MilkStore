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
            // Kiểm tra mã voucher có đúng 6 ký tự không
            if (!string.IsNullOrWhiteSpace(voucherModel.VoucherCode) && voucherModel.VoucherCode.Length != 6)
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Mã voucher phải có đúng 6 ký tự!");
            }

            // Kiểm tra mã Code đã nhập hay chưa, nếu chưa nhập thì sinh mã tự động
            if (string.IsNullOrWhiteSpace(voucherModel.VoucherCode))
            {
                voucherModel.VoucherCode = GenerateVoucherCode(6);  // Tạo mã voucher tự động nếu người dùng không nhập
            }

            // Kiểm tra tính duy nhất của mã voucher
            bool isCodeExisted = await _unitOfWork.GetRepository<Voucher>().Entities
                .AnyAsync(voucher => voucher.VoucherCode == voucherModel.VoucherCode && voucher.DeletedTime == null);

            if (isCodeExisted)
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Mã voucher đã tồn tại!");
            }

            Voucher newVoucher = _mapper.Map<Voucher>(voucherModel);
            newVoucher.CreatedTime = CoreHelper.SystemTimeNow;
            newVoucher.LastUpdatedTime = CoreHelper.SystemTimeNow;
            newVoucher.DeletedTime = null;

            await _unitOfWork.GetRepository<Voucher>().InsertAsync(newVoucher);
            await _unitOfWork.SaveAsync();
        }
        private string GenerateVoucherCode(int length)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            Random random = new Random();
            return new string(Enumerable.Repeat(chars, length)
              .Select(s => s[random.Next(s.Length)]).ToArray());
        }

        public async Task DeleteVoucher(string id)
        {
            if (string.IsNullOrWhiteSpace(id))
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Vui lòng nhập ID của voucher!");
            }

            Voucher? voucher = await _unitOfWork.GetRepository<Voucher>().GetByIdAsync(id)
                ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, $"Không tìm thấy voucher với ID {id}");

            if (voucher.DeletedTime != null)
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, "Voucher này đã bị xóa trước đó!");
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
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Vui lòng nhập ID voucher!");
            }

            Voucher? existingVoucher = await _unitOfWork.GetRepository<Voucher>().GetByIdAsync(id)
                ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, $"Không tìm thấy voucher với ID {id}");

            // Kiểm tra mã voucher có đúng 6 ký tự không
            if (!string.IsNullOrWhiteSpace(voucherModel.VoucherCode) && voucherModel.VoucherCode.Length != 6)
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Mã voucher phải có đúng 6 ký tự!");
            }

            // Nếu không nhập mã code, tạo mã voucher tự động
            if (string.IsNullOrWhiteSpace(voucherModel.VoucherCode))
            {
                voucherModel.VoucherCode = GenerateVoucherCode(6);  // Tạo mã voucher tự động nếu người dùng không nhập
            }

            // Kiểm tra nếu mã Code bị trùng với mã của các voucher khác (ngoại trừ voucher hiện tại)
            if (!string.IsNullOrWhiteSpace(voucherModel.VoucherCode) && voucherModel.VoucherCode != existingVoucher.VoucherCode)
            {
                bool isCodeExisted = await _unitOfWork.GetRepository<Voucher>().Entities
                    .AnyAsync(voucher => voucher.VoucherCode == voucherModel.VoucherCode && voucher.DeletedTime == null && voucher.Id != id);

                if (isCodeExisted)
                {
                    throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Mã voucher bị trùng lặp!");
                }
            }

            // Ánh xạ dữ liệu từ voucherModel sang existingVoucher
            _mapper.Map(voucherModel, existingVoucher);

            // Cập nhật thời gian chỉnh sửa cuối cùng
            existingVoucher.LastUpdatedTime = CoreHelper.SystemTimeNow;

            await _unitOfWork.GetRepository<Voucher>().UpdateAsync(existingVoucher);
            await _unitOfWork.SaveAsync();
        }



    }
}
