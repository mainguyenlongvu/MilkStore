using AutoMapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using MilkStore.Contract.Repositories.Entity;
using MilkStore.Contract.Services.Interface;
using MilkStore.Core.Base;
using MilkStore.Core.Constants;
using MilkStore.ModelViews.ReviewsModelView;


namespace MilkStore.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ReviewsController : ControllerBase
    {
        private readonly IReviewsService _reviewsService;
        public ReviewsController(IReviewsService reviewsService, IMapper mapper)
        {
            _reviewsService = reviewsService;
        }
        [HttpGet]
        public async Task<IActionResult> GetReviews(string? id, int page = 1, int pageSize = 10)
        {
            IList<Review> reviews = (IList<Review>)await _reviewsService.GetReviews(id, page, pageSize);
            return Ok(BaseResponse<IList<Review>>.OkResponse(reviews));
        }
        [HttpPost()]
        [Authorize(Roles = "Member")]
        public async Task<IActionResult> CreateReviews(ReviewsModel reviewsModel)
        {            
            await _reviewsService.CreateReviews(reviewsModel);
            return Ok(BaseResponse<string>.OkResponse("Thêm đánh giá thành công!"));
        }
        [HttpPut("{id}")]
        [Authorize(Roles = "Member")]
        public async Task<IActionResult> UpdateReview(string id, [FromBody] ReviewsModel reviewsModel)
        {
            Review Reviews = await _reviewsService.UpdateReviews(id, reviewsModel);
            return Ok(BaseResponse<Review>.OkResponse(Reviews));            
        }
        [HttpDelete("{id}")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> DeleteReview(string id)
        {
            await _reviewsService.DeletReviews(id);
            return Ok(BaseResponse<string>.OkResponse("Xóa đánh giá thành công!"));
        }
    }
}

