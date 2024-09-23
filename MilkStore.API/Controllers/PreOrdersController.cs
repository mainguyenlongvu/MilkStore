using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using MilkStore.Contract.Repositories.Entity;
using MilkStore.Contract.Services.Interface;
using MilkStore.Core.Base;
using MilkStore.ModelViews.PreOrdersModelView;

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
        [Authorize(Roles = "Member")]
        public async Task<IActionResult> GetPreOrders(string? id, int page = 1, int pageSize = 10)
        {
            IList<PreOrders> preords = (IList<PreOrders>)await _preOrdersService.GetPreOrders(id, page, pageSize);
            return Ok(BaseResponse<IList<PreOrders>>.OkResponse(preords));
        }
        [HttpPost()]
        [Authorize(Roles = "Member")]
        public async Task<IActionResult> CreatePreOrders(PreOrdersModelView preOrdersModel)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(new BaseException.BadRequestException("BadRequest", ModelState.ToString()));
            }
            PreOrders PreOrder = await _preOrdersService.CreatePreOrders(preOrdersModel);
            return Ok(BaseResponse<PreOrders>.OkResponse(PreOrder));
        }
        [HttpPut("{id}")]
        [Authorize(Roles = "Member")]
        public async Task<IActionResult> UpdatePreOrder(string id, [FromBody] PreOrdersModelView preOrdersModel)
        {
            if (!ModelState.IsValid)
            {
                return NotFound($"Pre-order have ID: {id} was not found.");
            }

            try
            {
                PreOrders PreOrder = await _preOrdersService.UpdatePreOrders(id, preOrdersModel);
                return Ok(BaseResponse<PreOrders>.OkResponse(PreOrder));
            }
            catch (Exception ex)
            {
                return NotFound(new { message = ex.Message });
            }
        }
        [HttpDelete("{id}")]
        [Authorize(Roles = "Member")]
        public async Task<IActionResult> DeletePreOrder(string id)
        {
            await _preOrdersService.DeletePreOrders(id);
            return Ok();
        }
    }
}
