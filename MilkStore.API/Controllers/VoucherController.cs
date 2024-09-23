using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using MilkStore.Contract.Repositories.Entity;
using MilkStore.Contract.Services.Interface;
using MilkStore.Core;
using MilkStore.Core.Base;
using MilkStore.ModelViews.VoucherModelViews;
using MilkStore.Repositories.Entity;

namespace MilkStore.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]

    public class VoucherController : ControllerBase
    {
        private readonly IVoucherService _voucherService;
        public VoucherController(IVoucherService vouchertService)
        {
            _voucherService = vouchertService;
        }
        [HttpGet()]
        public async Task<IActionResult> GetVouchers(string? name, int pageIndex = 1, int pageSize = 10)
        {
            var paginatedVouchers = await _voucherService.GetVouchers(name, pageIndex, pageSize);
            return Ok(BaseResponse<BasePaginatedList<Voucher>>.OkResponse(paginatedVouchers));
        }
        //[Authorize(Roles = "Staff")]
        [HttpPost()]
        public async Task<IActionResult> CreateVoucher(VoucherModelView voucherModel)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(new BaseException.BadRequestException("BadRequest", ModelState.ToString()));
            }
            Voucher voucher = await _voucherService.CreateVoucher(voucherModel);
            return Ok(BaseResponse<Voucher>.OkResponse(voucher));
        }
        //[Authorize(Roles = "Staff")]
        [HttpPut("{id}")]
        public async Task<IActionResult> UpdateVoucher(string id, VoucherModelView voucherModel)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(new BaseException.BadRequestException("BadRequest", ModelState.ToString()));
            }
            Voucher voucher = await _voucherService.UpdateVoucher(id, voucherModel);
            return Ok(BaseResponse<Voucher>.OkResponse(voucher));
        }
        //[Authorize(Roles = "Staff")]
        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteVoucher(string id)
        {
            await _voucherService.DeleteVoucher(id);
            return Ok();
        }
    }
}
