using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using MilkStore.Contract.Repositories.Entity;
using MilkStore.Contract.Services.Interface;
using MilkStore.Core.Base;
using MilkStore.Core;
using MilkStore.ModelViews.GiftModelViews;
using Microsoft.AspNetCore.Authorization;
using MilkStore.Services.Service;
using System.Drawing.Printing;

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
        //[Authorize(Roles = "Admin,Member")]
        public async Task<IActionResult> GetGift(string? id, int PageIndex, int PageSize)
        {
            var result = await _GiftService.GetGift(id, PageIndex, PageSize);
            return Ok(result);
        }



        //[HttpGet("GetPagging")]
        ////[Authorize(Roles = "Admin,Member")]
        //public async Task<IActionResult> Paging(int index, int size)
        //{
        //    BasePaginatedList<Gift> paging = await _GiftService.PagingGift(index, size);
        //    return Ok(paging);
        //}

        [HttpPost()]
        //[Authorize(Roles = "Admin")]
        public async Task<IActionResult> CreateGift(GiftModel GiftModel)
        {
            await _GiftService.CreateGift(GiftModel);
            return Ok(BaseResponse<string>.OkResponse("Added successfully"));
        }

        [HttpPut("{id}")]
        //[Authorize(Roles = "Admin")]
        public async Task<IActionResult> UpdateProduct(string id, [FromBody] GiftModel GiftModel)
        {
            await _GiftService.UpdateGift(id, GiftModel);
            return Ok(BaseResponse<string>.OkResponse("Updated successfully"));
            
        }

        [HttpDelete("{id}")]
        //[Authorize(Roles = "Admin")]
        public async Task<IActionResult> DeleteProduct(string id)
        {
            await _GiftService.DeleteGift(id);
            return Ok(BaseResponse<string>.OkResponse("Deleted successfully"));
        }
    }
}
