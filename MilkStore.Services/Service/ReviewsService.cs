using AutoMapper;
using Microsoft.EntityFrameworkCore;
using MilkStore.Contract.Repositories.Entity;
using MilkStore.Contract.Repositories.Interface;
using MilkStore.Contract.Services.Interface;
using MilkStore.Core.Utils;
using MilkStore.ModelViews.PreOrdersModelView;
using MilkStore.ModelViews.ProductsModelViews;
using MilkStore.ModelViews.ReviewsModelView;
using MilkStore.Repositories.Context;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MilkStore.Services.Service
{
    public class ReviewsService : IReviewsService
    {
        private readonly IUnitOfWork _unitOfWork;
        private readonly DatabaseContext _context;
        private readonly IMapper _mapper;
        public ReviewsService(DatabaseContext context, IUnitOfWork unitOfWork, IMapper mapper)
        {
            _context = context;
            _unitOfWork = unitOfWork;
            _mapper = mapper;
        }

        public async Task<Review> CreateReviews(ReviewsModel reviewsModel)
        {
            //var newReview = new Review
            //{
            //    ProductId = reviewsModel.ProductId,
            //    UserId = reviewsModel.UserId,
            //    Rating = reviewsModel.Rating,
            //    Comment = reviewsModel.Comment,
            //};
            Review newReview = _mapper.Map<Review>(reviewsModel);
            newReview.CreatedTime = DateTime.UtcNow;
            await _unitOfWork.GetRepository<Review>().InsertAsync(newReview);
            await _unitOfWork.SaveAsync();
            return newReview;
        }

        public async Task DeletReviews(string id)
        {
            Review review = await _unitOfWork.GetRepository<Review>().GetByIdAsync(id);
            if (review == null)
            {
                throw new KeyNotFoundException($"Review with ID {id} was not found.");
            }
            review.DeletedTime = CoreHelper.SystemTimeNow;
            await _unitOfWork.GetRepository<Review>().UpdateAsync(review);
            await _unitOfWork.SaveAsync();
        }

        public async Task<IEnumerable<Review>> GetReviews(string? id, int page, int pageSize)
        {
            if (id == null)
            {
                var query = _unitOfWork.GetRepository<Review>()
                    .Entities
                    .Where(detail => detail.DeletedTime == null)
                    .OrderBy(detail => detail.ProductID);


                var paginated = await _unitOfWork.GetRepository<Review>()
                .GetPagging(query, page, pageSize);

                return paginated.Items;

            }
            else
            {
                var review = await _unitOfWork.GetRepository<Review>()
                    .Entities
                    .FirstOrDefaultAsync(r => r.Id == id && r.DeletedTime == null);
                if (review == null)
                {
                    throw new KeyNotFoundException($"Review have ID: {id} was not found.");
                }
                return _mapper.Map<List<Review>>(review);
            }

        }

        public async Task<Review> UpdateReviews(string id, ReviewsModel reviewsModel)
        {

            Review review = await _unitOfWork.GetRepository<Review>().GetByIdAsync(id);

            if (review == null)
            {
                throw new Exception($"Review have ID: {id} was not found.");
            }

            //review.ProductId = reviewsModel.ProductId;
            //review.UserId = reviewsModel.UserId;
            //review.Rating = reviewsModel.Rating;
            //review.Comment = reviewsModel.Comment;
            _mapper.Map(reviewsModel, review);
            review.LastUpdatedTime = DateTime.UtcNow;
            await _unitOfWork.GetRepository<Review>().UpdateAsync(review);
            await _unitOfWork.SaveAsync();
            return review;
        }
    }
}
