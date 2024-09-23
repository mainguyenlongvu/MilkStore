using AutoMapper;
using MilkStore.Contract.Repositories.Entity;
using MilkStore.ModelViews.ResponseDTO;
using MilkStore.ModelViews.OrderModelViews;
using MilkStore.ModelViews.ProductsModelViews;
using MilkStore.ModelViews.UserModelViews;
using MilkStore.Repositories.Entity;
using MilkStore.ModelViews.OrderDetailsModelView;
using MilkStore.ModelViews.CategoryModelViews;
using MilkStore.ModelViews.ReviewsModelView;
using MilkStore.ModelViews.PreOrdersModelView;
using MilkStore.ModelViews.PostModelViews;
using MilkStore.ModelViews.VoucherModelViews;


namespace MilkStore.Services.Mapping
{

    public class MappingProfile : Profile
    {
        public MappingProfile()
        {

            CreateMap<ApplicationUser, LoginGoogleModel>().ReverseMap();




            CreateMap<Category, CategoryModel>();
            CreateMap<CategoryModel, Category>();

            #region Post
            CreateMap<PostModelView, Post>();
            CreateMap<Post, PostResponseDTO>()
                .ForMember(dest => dest.Products, opt => opt.MapFrom(src => src.PostProducts.Select(pp => new ProductResponseDTO
                {
                    ProductID = pp.Product.Id,
                    ProductName = pp.Product.ProductName,
                    Description = pp.Product.Description,
                    Price = pp.Product.Price,
                    QuantityInStock = pp.Product.QuantityInStock,
                    ImageUrl = pp.Product.ImageUrl,
                    CategoryId = pp.Product.CategoryId
                }).ToList()));
            #endregion

            CreateMap<Products, ProductsModel>();
            CreateMap<ProductsModel, Products>();

            CreateMap<UserModelView, ApplicationUser>()
            .ForMember(dest => dest.Points, opt => opt.MapFrom(src => 0)) // Set Points to 0
            .ForMember(dest => dest.CreatedTime, opt => opt.MapFrom(src => DateTimeOffset.UtcNow));

            CreateMap<UserModelView, ApplicationUser>()
            .ForMember(dest => dest.LastUpdatedBy, opt => opt.Ignore())
            .ForMember(dest => dest.LastUpdatedTime, opt => opt.Ignore())
            .ForMember(dest => dest.Points, opt => opt.Ignore()); // Nếu không muốn ánh xạ Points

            CreateMap<OrderModelView, Order>().ReverseMap();
            CreateMap<Order, OrderResponseDTO>()
                .ForMember(dest => dest.OrderDetailss, opt => opt.MapFrom(src => src.OrderDetailss));

            CreateMap<OrderDetailsModelView, OrderDetails>();
            CreateMap<OrderDetails, OrderDetailResponseDTO>()
            .ForMember(dest => dest.UnitPrice, opt => opt.Ignore()); //

            CreateMap<OrderDetails, OrderDetailResponseDTO>();

            // Ánh xạ từ OrderModelView sang Order, nhưng chỉ cập nhật các thuộc tính thay đổi
            CreateMap<OrderModelView, Order>()
                .ForAllMembers(opts => opts.Condition((src, dest, srcMember) => srcMember != null)); // Chỉ ánh xạ khi giá trị mới khác null

            CreateMap<Review, ReviewsModel>().ReverseMap();
            CreateMap<PreOrders, PreOrdersModelView>().ReverseMap();

            CreateMap<Voucher, VoucherModelView>().ReverseMap();
        }
    }
}
