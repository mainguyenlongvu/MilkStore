using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using MilkStore.Contract.Services.Interface;
using MilkStore.Core.Base;
using MilkStore.ModelViews.CategoryModelViews;
using MilkStore.Contract.Repositories.Entity;
using Microsoft.AspNetCore.Authorization;
using MilkStore.Core;
using MilkStore.ModelViews.ResponseDTO;
namespace MilkStore.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class CategoryController : ControllerBase
    {
        private readonly ICategoryService _CategoryService;
        public CategoryController(ICategoryService CategoryService)
        {
            _CategoryService = CategoryService;
        }
        [HttpGet]
        //[Authorize(Roles = "Admin,Member")]
        public async Task<IActionResult> GetCategory(string? id)
        {
            IEnumerable<CategoryResponseDTO>? Category = await _CategoryService.GetCategory(id);
            return Ok(Category);
        }
        [HttpPost()]
        //[Authorize(Roles = "Admin")]
        public async Task<IActionResult> CreateCategory(CategoryModel CategoryModel)
        {
            await _CategoryService.CreateCategory(CategoryModel);
            return Ok(BaseResponse<string>.OkResponse("Added successfully"));
        }
        [HttpPut("{id}")]
        //[Authorize(Roles = "Admin")]
        public async Task<IActionResult> UpdateProduct(string id, [FromBody] CategoryModel CategoryModel)
        {
            await _CategoryService.UpdateCategory(id, CategoryModel);
            return Ok(BaseResponse<string>.OkResponse("Updated successfully"));
        }
        [HttpDelete("{id}")]
        //[Authorize(Roles = "Admin")]
        public async Task<IActionResult> DeleteProduct(string id)
        {
            await _CategoryService.DeleteCategory(id);
            return Ok(BaseResponse<string>.OkResponse("Deleted successfully"));
        }
    }
}

