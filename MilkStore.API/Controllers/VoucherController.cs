using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using MilkStore.Contract.Services.Interface;
using MilkStore.Core;
using MilkStore.Core.Base;
using MilkStore.ModelViews.VoucherModelViews;
using MilkStore.ModelViews.ResponseDTO;


namespace MilkStore.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class VoucherController : ControllerBase
    {
        private readonly IVoucherService _voucherService;

        public VoucherController(IVoucherService voucherService)
        {
            _voucherService = voucherService;
        }

        [HttpGet()]
        public async Task<IActionResult> GetVouchers(string? name, int index = 1, int pageSize = 10)
        {
            BasePaginatedList<VoucherResponseDTO>? paginatedVouchers = await _voucherService.GetVouchers(name, index, pageSize);
            return Ok(BaseResponse<BasePaginatedList<VoucherResponseDTO>>.OkResponse(paginatedVouchers));
        }

        [Authorize(Roles = "Staff")]
        [HttpPost()]
        public async Task<IActionResult> CreateVoucher(VoucherModelView voucherModel)
        {
            await _voucherService.CreateVoucher(voucherModel);
            return Ok(BaseResponse<string>.OkResponse("Tạo voucher thành công!"));
        }

        [Authorize(Roles = "Staff")]
        [HttpPut("{id}")]
        public async Task<IActionResult> UpdateVoucher(string id, VoucherModelView voucherModel)
        {
            await _voucherService.UpdateVoucher(id, voucherModel);
            return Ok(BaseResponse<string>.OkResponse("Cập nhật voucher thành công!"));
        }

        [Authorize(Roles = "Staff")]
        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteVoucher(string id)
        {
            await _voucherService.DeleteVoucher(id);
            return Ok(BaseResponse<string>.OkResponse("Xóa voucher thành công!"));
        }
    }
}

