using AutoMapper;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using MilkStore.Contract.Repositories.Entity;
using MilkStore.Contract.Repositories.Interface;
using MilkStore.Contract.Services.Interface;
using MilkStore.Core;
using MilkStore.Core.Base;
using MilkStore.Core.Constants;
using MilkStore.Core.Utils;
using MilkStore.ModelViews.PostModelViews;
using MilkStore.ModelViews.ResponseDTO;
using System.Security.Claims;

namespace MilkStore.Services.Service
{
    public class PostService : IPostService
    {
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMapper _mapper;

        public PostService(IUnitOfWork unitOfWork, IMapper mapper, IHttpContextAccessor httpContextAccessor)
        {
            _unitOfWork = unitOfWork;
            _mapper = mapper;
            _httpContextAccessor = httpContextAccessor;
        }
        public async Task CreatePost(PostModelView postModel)
        {
            string? userID = _httpContextAccessor.HttpContext.User?.FindFirst(ClaimTypes.NameIdentifier).Value;
            if (string.IsNullOrWhiteSpace(userID))
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.Unauthorized, ErrorCode.Unauthorized, "Please log in!");
            }
            Post newPost = _mapper.Map<Post>(postModel);
            newPost.CreatedTime = CoreHelper.SystemTimeNow;
            newPost.DeletedTime = null;
            newPost.CreatedBy = userID;

            // Thêm sản phẩm vào bài đăng bằng PostProduct
            if (postModel.ProductIDs != null && postModel.ProductIDs.Any())
            {
                newPost.PostProducts = new List<PostProduct>();

                foreach (string productId in postModel.ProductIDs)
                {
                    Products? product = await _unitOfWork.GetRepository<Products>().GetByIdAsync(productId);
                    if (product != null && product.DeletedTime == null)
                    {
                        newPost.PostProducts.Add(new PostProduct
                        {
                            Post = newPost,
                            Product = product
                        });
                    }
                    else if (product == null)
                    {
                        throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, $"Product with {productId} not found!");
                    }
                    else
                    {
                        throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, "Product has been deleted or does not exist!");
                    }
                }
            }
            await _unitOfWork.GetRepository<Post>().InsertAsync(newPost);
            await _unitOfWork.SaveAsync();
        }

        public async Task DeletePost(string id)
        {
            if (string.IsNullOrWhiteSpace(id))
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Please enter postID!");
            }
            Post? post = await _unitOfWork.GetRepository<Post>().GetByIdAsync(id)
                 ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, $"No products found with {id}");
            if (post.DeletedTime != null)
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, "This post has already been deleted!");
            }
            post.DeletedTime = CoreHelper.SystemTimeNow;
            await _unitOfWork.GetRepository<Post>().UpdateAsync(post);
            await _unitOfWork.SaveAsync();
        }

        public async Task<BasePaginatedList<PostResponseDTO>> GetPosts(string? id, string? name, int pageIndex, int pageSize)
        {
            IQueryable<Post>? query = _unitOfWork.GetRepository<Post>().Entities.AsNoTracking().Where(post => post.DeletedTime == null);
            if (!string.IsNullOrWhiteSpace(id))
            {
                query = query.Where(post => post.Id == id);
            }
            if (!string.IsNullOrWhiteSpace(name))
            {
                query = query.Where(post => post.Title.Contains(name));
            }
            BasePaginatedList<Post>? paginatedPosts = await _unitOfWork.GetRepository<Post>().GetPagging(query, pageIndex, pageSize);

            if (!paginatedPosts.Items.Any())
            {
                if (!string.IsNullOrWhiteSpace(id))
                {
                    Post? postById = await _unitOfWork.GetRepository<Post>().Entities
                        .FirstOrDefaultAsync(post => post.Id == id && post.DeletedTime == null);
                    if (postById != null)
                    {
                        PostResponseDTO? postDto = _mapper.Map<PostResponseDTO>(postById);
                        return new BasePaginatedList<PostResponseDTO>(new List<PostResponseDTO> { postDto }, 1, 1, 1);
                    }
                }

                if (!string.IsNullOrWhiteSpace(name))
                {
                    List<Post>? postsByName = await _unitOfWork.GetRepository<Post>().Entities
                        .Where(post => post.Title.Contains(name) && post.DeletedTime == null)
                        .ToListAsync();
                    if (postsByName.Any())
                    {
                        List<PostResponseDTO>? paginatedPostDtos = _mapper.Map<List<PostResponseDTO>>(postsByName);
                        return new BasePaginatedList<PostResponseDTO>(paginatedPostDtos, 1, 1, postsByName.Count());
                    }
                }
            }
            //GetAll
            List<PostResponseDTO>? postDtosResult = _mapper.Map<List<PostResponseDTO>>(paginatedPosts.Items);
            return new BasePaginatedList<PostResponseDTO>(
                postDtosResult,
                paginatedPosts.TotalItems,
                paginatedPosts.CurrentPage,
                paginatedPosts.PageSize
            );
        }

        public async Task UpdatePost(string id, PostModelView postModel)
        {
            string userID = _httpContextAccessor.HttpContext.User.FindFirst(ClaimTypes.NameIdentifier).Value;
            if (!string.IsNullOrWhiteSpace(userID))
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.Unauthorized, ErrorCode.Unauthorized, "Please log in!");
            }
            if (string.IsNullOrWhiteSpace(id))
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Please enter postID!");
            }
            Post? post = await _unitOfWork.GetRepository<Post>().GetByIdAsync(id)
             ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, $"No review found with {id}!");

            //map từ PostModelView sang Post (chỉ cập nhật các trường thay đổi)
            _mapper.Map(postModel, post);

            post.LastUpdatedTime = CoreHelper.SystemTimeNow;
            post.LastUpdatedBy = userID;

            // Kiểm tra xem sản phẩm có bị xóa chưa, thêm sản phẩm nếu cần
            if (postModel.ProductIDs != null && postModel.ProductIDs.Any())
            {
                post.PostProducts = new List<PostProduct>();

                foreach (string productId in postModel.ProductIDs)
                {
                    Products? product = await _unitOfWork.GetRepository<Products>().GetByIdAsync(productId);
                    if (product != null)
                    {
                        post.PostProducts.Add(new PostProduct
                        {
                            Post = post,
                            Product = product
                        });
                    }
                    else
                    {
                        throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, $"No product found with {productId}!");
                    }
                }
            }
            await _unitOfWork.GetRepository<Post>().UpdateAsync(post);
            await _unitOfWork.SaveAsync();
        }
    }
}

