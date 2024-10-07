using Microsoft.AspNetCore.Mvc;
using MilkStore.Contract.Services.Interface;
using MilkStore.Core.Base;
using MilkStore.ModelViews.ProductsModelViews;
using MilkStore.ModelViews.ResponseDTO;

namespace MilkStore.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ProductsController : ControllerBase
    {
        private readonly IProductsService _ProductsService;
        public ProductsController(IProductsService ProductsService)
        {
            _ProductsService = ProductsService;
        }
        [HttpGet("GetProduct & Pagging")]
        //[Authorize(Roles = "Admin,Member")]
        public async Task<IActionResult> GetProducts(string? id, int pageIndex, int pageSize)

        {
            var result = await _ProductsService.GetProducts(id, pageIndex, pageSize);
            return Ok(result);
            
        }
        [HttpGet("GetByName")]
        public async Task<IActionResult> GetByName(string? Productname, string? CategoryName)
        {
            IEnumerable<ProductResponseDTO> product = await _ProductsService.GetProductsName(Productname, CategoryName);
            return Ok(product);
        }
        [HttpPost()]
        //[Authorize(Roles = "Admin")]
        public async Task<IActionResult> CreateProducts(ProductsModel ProductsModel)
        {
            await _ProductsService.CreateProducts(ProductsModel);
            return Ok(BaseResponse<string>.OkResponse("Added successfully"));
        }
        [HttpPut("{id}")]
        //[Authorize(Roles = "Admin")]
        public async Task<IActionResult> UpdateProduct(string id, [FromBody] ProductsModel productsModel)
        {
            await _ProductsService.UpdateProducts(id, productsModel);
            return Ok(BaseResponse<string>.OkResponse("Updated successfully"));
        }
        [HttpDelete("{id}")]
        //[Authorize(Roles = "Admin")]
        public async Task<IActionResult> DeleteProduct(string id)
        {
            await _ProductsService.DeleteProducts(id);
            return Ok(BaseResponse<string>.OkResponse("Deleted successfully"));
        }
    }
}
