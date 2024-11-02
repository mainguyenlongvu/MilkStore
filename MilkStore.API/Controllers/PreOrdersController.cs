using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using MilkStore.Contract.Repositories.Entity;
using MilkStore.Contract.Services.Interface;
using MilkStore.Core.Base;
using MilkStore.ModelViews.PreOrdersModelView;
using MilkStore.Services.Service;

namespace MilkStore.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class PreOrdersController : ControllerBase
    {
        private readonly IPreOrdersService _preOrdersService;
        public PreOrdersController(IPreOrdersService preOrdersService)
        {
            _preOrdersService = preOrdersService;
        }
        [HttpGet]
        public async Task<IActionResult> GetPreOders(string? id, int pageIndex, int pageSize)
        {
            var result = await _preOrdersService.GetPreOders(id, pageIndex, pageSize);
            return Ok(result);
        }
        [HttpPost()]
        [Authorize(Roles = "Member")]
        public async Task<IActionResult> CreatePreOrders(PreOrdersModelView preOrdersModel)
        {
            await _preOrdersService.CreatePreOrders(preOrdersModel);

            return Ok(BaseResponse<string>.OkResponse("Đặt hàng trước thành công!"));
        }
        [HttpDelete("{id}")]
        [Authorize(Roles = "Member")]
        public async Task<IActionResult> DeletePreOrder(string id)
        {
            await _preOrdersService.DeletePreOrders(id);
            return Ok(BaseResponse<string>.OkResponse("Xóa đơn hàng đặt trước thành công!"));
        }
    }
}
