using AutoMapper;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using MilkStore.Contract.Repositories.Entity;
using MilkStore.Contract.Repositories.Interface;
using MilkStore.Contract.Services.Interface;
using MilkStore.Core;
using MilkStore.Core.Utils;
using MilkStore.ModelViews.PostModelViews;
using MilkStore.ModelViews.ResponseDTO;
using MilkStore.Repositories.Context;

namespace MilkStore.Services.Service
{
    public class PostService : IPostService
    {
        private readonly IUnitOfWork _unitOfWork;        
        private readonly IMapper _mapper;
        public PostService(IUnitOfWork unitOfWork, IMapper mapper)
        {            
            _unitOfWork = unitOfWork;
            _mapper = mapper;
        }

        public async Task CreatePost(PostModelView postModel)
        {
            Post newPost = _mapper.Map<Post>(postModel);
            newPost.CreatedTime = CoreHelper.SystemTimeNow;
            newPost.DeletedTime = null;
            // Thêm sản phẩm vào bài đăng bằng PostProduct
            if (postModel.ProductIDs != null && postModel.ProductIDs.Any())
            {
                newPost.PostProducts = new List<PostProduct>();

                foreach (var productId in postModel.ProductIDs)
                {                    
                    var product = await _unitOfWork.GetRepository<Products>().GetByIdAsync(productId);
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
                        throw new KeyNotFoundException($"Product with ID {productId} was not found.");
                    }
                    else
                    {
                        throw new InvalidOperationException($"Product with ID {productId} has been deleted.");
                    }
                }
            }
            await _unitOfWork.GetRepository<Post>().InsertAsync(newPost);
            await _unitOfWork.SaveAsync();            
        }
        
        public async Task DeletePost(string id)
        {            
            Post post = await _unitOfWork.GetRepository<Post>().GetByIdAsync(id);            
            if (post == null)
            {
                throw new KeyNotFoundException($"Post with ID {id} was not found.");
            }
            if (post.DeletedTime != null)
            {
                throw new InvalidOperationException($"Post with ID {id} has already been deleted.");
            }
            post.DeletedTime = CoreHelper.SystemTimeNow;
            await _unitOfWork.GetRepository<Post>().UpdateAsync(post);
            await _unitOfWork.SaveAsync();
        }
        
        public async Task<BasePaginatedList<PostResponseDTO>> GetPosts(string? id, string? name, int pageIndex, int pageSize)
        {            
            var query = _unitOfWork.GetRepository<Post>().Entities.Where(post => post.DeletedTime == null);
            if (!id.IsNullOrEmpty())
            {
                query = query.Where(post => post.Id == id);
            }
            if (!name.IsNullOrEmpty())
            {
                query = query.Where(post => post.Title.Contains(name));
            }
            var paginatedPosts = await _unitOfWork.GetRepository<Post>().GetPagging(query, pageIndex, pageSize);

            if (!paginatedPosts.Items.Any())
            {
                if (!id.IsNullOrEmpty())
                {
                    var postById = await _unitOfWork.GetRepository<Post>().Entities
                        .FirstOrDefaultAsync(post => post.Id == id && post.DeletedTime == null);
                    if (postById != null)
                    {
                        var postDto = _mapper.Map<PostResponseDTO>(postById);
                        return new BasePaginatedList<PostResponseDTO>(new List<PostResponseDTO> { postDto }, 1, 1, 1);
                    }
                }

                if (!name.IsNullOrEmpty())
                {
                    var postsByName = await _unitOfWork.GetRepository<Post>().Entities
                        .Where(post => post.Title.Contains(name) && post.DeletedTime == null)
                        .ToListAsync();
                    if (postsByName.Any())
                    {
                        var paginatedPostDtos = _mapper.Map<List<PostResponseDTO>>(postsByName);
                        return new BasePaginatedList<PostResponseDTO>(paginatedPostDtos, 1, 1, postsByName.Count());
                    }
                }
            }

            //GetAll
            var postDtosResult = _mapper.Map<List<PostResponseDTO>>(paginatedPosts.Items);

            return new BasePaginatedList<PostResponseDTO>(
                postDtosResult,
                paginatedPosts.TotalItems,
                paginatedPosts.CurrentPage,
                paginatedPosts.PageSize
            );            
        }
             
        public async Task UpdatePost(string id, PostModelView postModel)
        {            
            Post post = await _unitOfWork.GetRepository<Post>().GetByIdAsync(id);            
            if (post == null)
            {
                throw new KeyNotFoundException($"Post with ID {id} was not found.");
            }

            //map từ PostModelView sang Post (chỉ cập nhật các trường thay đổi)
            _mapper.Map(postModel, post);
            
            post.LastUpdatedTime = CoreHelper.SystemTimeNow;

            // Kiểm tra xem sản phẩm có bị xóa chưa, thêm sản phẩm nếu cần
            if (postModel.ProductIDs != null && postModel.ProductIDs.Any())
            {
                post.PostProducts = new List<PostProduct>();

                foreach (var productId in postModel.ProductIDs)
                {
                    var product = await _unitOfWork.GetRepository<Products>().GetByIdAsync(productId);
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
                        throw new KeyNotFoundException($"Product with ID {productId} was not found.");
                    }
                }
            }
            
            await _unitOfWork.GetRepository<Post>().UpdateAsync(post);
            await _unitOfWork.SaveAsync();            
        }



    }
}
