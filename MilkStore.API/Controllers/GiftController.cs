using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using MilkStore.Contract.Repositories.Entity;
using MilkStore.Contract.Services.Interface;
using MilkStore.Core.Base;
using MilkStore.Core;
using MilkStore.ModelViews.GiftModelViews;
using Microsoft.AspNetCore.Authorization;

namespace MilkStore.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class GiftController : ControllerBase
    {
        private readonly IGiftService _GiftService;
        public GiftController(IGiftService GiftService)
        {
            _GiftService = GiftService;
        }

        [HttpGet]
        [Authorize(Roles = "Admin,Member")]
        public async Task<IActionResult> GetGift(string? id)
        {
            try
            {
                IEnumerable<GiftModel> Gift = await _GiftService.GetGift(id);

                if (Gift == null || !Gift.Any())
                {
                    return NotFound("Sản phẩm không tồn tại!!!");
                }

                return Ok(Gift);
            }
            catch (Exception ex)
            {
                return StatusCode(500); // Trả về mã lỗi 500
            }
        }



        [HttpGet("GetPagging")]
        //[Authorize(Roles = "Admin,Member")]
        public async Task<IActionResult> Paging(int index, int size)
        {
            BasePaginatedList<Gift> paging = await _GiftService.PagingGift(index, size);
            return Ok(paging);
        }

        [HttpPost()]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> CreateGift(GiftModel GiftModel)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(new BaseException.BadRequestException("BadRequest", ModelState.ToString()));
            }

            Gift Gift = await _GiftService.CreateGift(GiftModel);
            return Ok(BaseResponse<Gift>.OkResponse(Gift));
        }

        [HttpPut("{id}")]
        //[Authorize(Roles = "Admin")]
        public async Task<IActionResult> UpdateProduct(string id, [FromBody] GiftModel GiftModel)
        {
            if (!ModelState.IsValid)
            {
                return NotFound("Sản phẩm không tồn tại!!!");
            }

            try
            {
                Gift updatedProduct = await _GiftService.UpdateGift(id, GiftModel);
                return Ok(updatedProduct);
            }
            catch (Exception ex)
            {
                return NotFound(new { message = ex.Message });
            }
        }

        [HttpDelete("{id}")]
        //[Authorize(Roles = "Admin")]
        public async Task<IActionResult> DeleteProduct(string id)
        {
            try
            {
                Gift deletedProduct = await _GiftService.DeleteGift(id);
                return Ok(deletedProduct); // Trả về sản phẩm đã bị xóa
            }
            catch (Exception ex)
            {
                return NotFound("Sản phẩm không tồn tại!!!"); // Trả về 404 nếu sản phẩm không tồn tại
            }
        }
    }
}
