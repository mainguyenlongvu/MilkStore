using AutoMapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using MilkStore.Contract.Repositories.Entity;
using MilkStore.Contract.Services.Interface;
using MilkStore.Core.Base;
using MilkStore.ModelViews.PostModelViews;
using MilkStore.ModelViews.PreOrdersModelView;
using MilkStore.ModelViews.ReviewsModelView;
using MilkStore.Services.Service;

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
        [Authorize(Roles = "Member")]
        public async Task<IActionResult> GetReviews(string? id, int page = 1, int pageSize = 10)
        {
            IList<Review> reviews = (IList<Review>)await _reviewsService.GetReviews(id, page, pageSize);
            return Ok(BaseResponse<IList<Review>>.OkResponse(reviews));
        }
        [HttpPost()]
        [Authorize(Roles = "Member")]
        public async Task<IActionResult> CreateReviews(ReviewsModel reviewsModel)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(new BaseException.BadRequestException("BadRequest", ModelState.ToString()));
            }
            Review Reviews = await _reviewsService.CreateReviews(reviewsModel);
            return Ok(BaseResponse<Review>.OkResponse(Reviews));
        }
        [HttpPut("{id}")]
        [Authorize(Roles = "Member")]
        public async Task<IActionResult> UpdateReview(string id, [FromBody] ReviewsModel reviewsModel)
        {
            if (!ModelState.IsValid)
            {
                return NotFound($"Review have ID: {id} was not found.");
            }

            try
            {
                Review Reviews = await _reviewsService.UpdateReviews(id, reviewsModel);
                return Ok(BaseResponse<Review>.OkResponse(Reviews));
            }
            catch (Exception ex)
            {
                return NotFound(new { message = ex.Message });
            }
        }
        [HttpDelete("{id}")]
        [Authorize(Roles = "Member")]
        public async Task<IActionResult> DeleteReview(string id)
        {
            await _reviewsService.DeletReviews(id);
            return Ok();
        }
    }
}
