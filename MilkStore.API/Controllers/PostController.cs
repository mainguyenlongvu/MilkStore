using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using MilkStore.Contract.Services.Interface;
using MilkStore.Core;
using MilkStore.Core.Base;
using MilkStore.Core.Constants;
using MilkStore.ModelViews.PostModelViews;
using MilkStore.ModelViews.ResponseDTO;

namespace MilkStore.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class PostController : ControllerBase
    {
        private readonly IPostService _postService;


        public PostController(IPostService postService)
        {
            _postService = postService;
        }
        [HttpGet()]
        public async Task<IActionResult> GetPost(string? id, string? name, int index = 1, int pageSize = 10)
        {
            BasePaginatedList<PostResponseDTO>? paginatedPosts = await _postService.GetPosts(id, name, index, pageSize);
            return Ok(BaseResponse<BasePaginatedList<PostResponseDTO>>.OkResponse(paginatedPosts));
        }
        [Authorize(Roles = "Staff")]
        [HttpPost()]
        public async Task<IActionResult> CreatePost(PostModelView postModel)
        {
            await _postService.CreatePost(postModel);
            return Ok(BaseResponse<string>.OkResponse("Thêm bài viết thành công!"));
        }
        [Authorize(Roles = "Staff")]
        [HttpPut("{id}")]
        public async Task<IActionResult> UpdatePost(string id, PostModelView postModel)
        {
            await _postService.UpdatePost(id, postModel);
            return Ok(BaseResponse<string>.OkResponse("Sửa bài viết thành công!"));
        }
        [Authorize(Roles = "Staff")]
        [HttpDelete("{id}")]
        public async Task<IActionResult> DeletePost(string id)
        {
            await _postService.DeletePost(id);
            return Ok(BaseResponse<string>.OkResponse("Xóa thành công!"));
        }
    }
}
